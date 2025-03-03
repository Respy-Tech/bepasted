import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { serveStatic } from '@hono/node-server/serve-static'
import mongoose from 'mongoose'
import { pasteRoutes } from './routes/paste.js'
import { setupCleanupScheduler } from './utils/maintenance/cleanup.js'
import { createPasteLimiter } from './utils/security/rate-limiter.js'
import { readFile } from 'fs/promises'
import { join } from 'path'
import crypto from 'crypto'
import { arcjetProtect } from './utils/http/arcjet-middleware.js'
import { getDomain } from './utils/config/domain.js'
import logger from './utils/logging/logger.js'
import { SIZE_LIMITS } from './utils/http/request-parser.js'
import { errorMiddleware, createError, ErrorTypes } from './utils/logging/error-handler.js'
import config from './utils/config/config.js'
import { updateOpenApiFiles } from './utils/config/updateOpenApiUrls.js'

// Web Streams API for request body handling
const { TextEncoder } = globalThis;

const app = new Hono();
const port = config.PORT

// Apply global error handling middleware
// This should be one of the first middleware to catch errors from all subsequent middleware
app.use('*', errorMiddleware);

// Global request size limiter to prevent DoS attacks
// This needs to be the first middleware to reject oversized requests early
app.use('*', async (c, next) => {
  // Skip for GET and OPTIONS requests as they don't have a body
  if (c.req.method === 'GET' || c.req.method === 'OPTIONS' || c.req.method === 'HEAD') {
    return next();
  }
  
  // Check Content-Length header for a quick rejection
  const contentLength = parseInt(c.req.header('content-length') || '0');
  const maxGlobalRequestSize = SIZE_LIMITS.requestSize;
  
  if (contentLength > maxGlobalRequestSize) {
    logger.warn('Global request size limit exceeded', {
      size: contentLength,
      maxSize: maxGlobalRequestSize,
      path: c.req.path,
      method: c.req.method,
      ip: c.req.header('cf-connecting-ip') || c.req.header('x-real-ip')
    });
    
    return c.json({
      error: 'Request entity too large',
      maxSize: `${(maxGlobalRequestSize / (1024 * 1024)).toFixed(1)}MB`
    }, 413); // 413 Payload Too Large
  }
  
  // Always read and cache the body for paste-related endpoints
  const isPasteEndpoint = c.req.path.includes('/paste');
  const contentType = c.req.header('content-type') || '';
  const shouldCacheBody = isPasteEndpoint || 
                         contentType.includes('application/json') || 
                         contentLength > maxGlobalRequestSize / 2;
  
  if (shouldCacheBody) {
    try {
      // Log that we're caching this request body
      logger.info('Caching request body for reuse', {
        path: c.req.path,
        size: contentLength,
        method: c.req.method
      });
      
      // Read the full body once and store it
      const originalReq = c.req.raw;
      const bodyText = await originalReq.text();
      
      // Check actual size after reading
      if (bodyText.length > maxGlobalRequestSize) {
        logger.warn('Request body exceeds size limit after reading', {
          actualSize: bodyText.length,
          contentLength,
          maxSize: maxGlobalRequestSize
        });
        
        return c.json({
          error: 'Request entity too large',
          maxSize: `${(maxGlobalRequestSize / (1024 * 1024)).toFixed(1)}MB`
        }, 413);
      }
      
      // Store the body in multiple places to ensure it can be accessed
      c.set('cachedRequestBody', bodyText);
      
      // Create a new body stream for the request
      const newBodyStream = new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(bodyText));
          controller.close();
        }
      });
      
      // Try to create a new Request with the cached body to replace the current one
      try {
        const newRequest = new Request(originalReq.url, {
          method: originalReq.method,
          headers: originalReq.headers,
          body: newBodyStream
        });
        
        // Replace the raw request with our new one that has a fresh body stream
        // Store reference to original request context
        newRequest._context = originalReq._context;
        newRequest._c = c;
        
        // Save a reference to the original request
        c.req.originalRaw = c.req.raw;
        c.req.raw = newRequest;
        
        logger.debug('Successfully created new request with cached body', {
          path: c.req.path,
          bodySize: bodyText.length
        });
      } catch (streamError) {
        // If replacing the request fails, just continue with the cached body
        logger.warn('Failed to create new request stream, but body is cached', {
          error: streamError.message,
          path: c.req.path
        });
      }
      
      // If this is a large but legitimate request, set a timeout
      if (bodyText.length > maxGlobalRequestSize / 2) {
        const requestTimeout = setTimeout(() => {
          logger.warn('Request processing timeout - potential DoS attempt', {
            path: c.req.path,
            size: bodyText.length,
            ip: c.req.header('cf-connecting-ip') || c.req.header('x-real-ip')
          });
        }, 30000); // 30 second timeout
        
        try {
          await next();
        } finally {
          clearTimeout(requestTimeout);
        }
        return;
      }
    } catch (error) {
      logger.error('Error processing request body in middleware', {
        error: error.message,
        stack: error.stack,
        path: c.req.path
      });
      
      // If there's an error reading the body, return a 400
      return c.json({
        error: 'Error processing request body',
        details: config.NODE_ENV === 'development' ? error.message : undefined
      }, 400);
    }
  }
  
  // For all other cases
  await next();
});

// Add CSRF protection
app.use('*', async (c, next) => {
  const csrfSecret = config.CSRF_SECRET;
  
  // For GET requests, generate and set a CSRF token
  if (c.req.method === 'GET' && !c.req.path.startsWith('/api/')) {
    const csrfToken = crypto.randomBytes(16).toString('hex');
    const csrfHash = crypto
      .createHmac('sha256', csrfSecret)
      .update(csrfToken)
      .digest('hex');
    
    c.set('csrfToken', csrfToken);
    c.header('X-CSRF-Token', csrfToken);
  }
  
  // For non-GET requests, validate the CSRF token
  if (c.req.method !== 'GET' && !c.req.path.startsWith('/api/health')) {
    const csrfToken = c.req.header('X-CSRF-Token');
    if (!csrfToken) {
      logger.warn('CSRF token missing', { path: c.req.path });
      return c.json({ error: 'CSRF token missing' }, 403);
    }
    
    // Generate the expected hash for this token
    const expectedHash = crypto
      .createHmac('sha256', csrfSecret)
      .update(csrfToken)
      .digest('hex');
    
    // Retrieve the saved token from session/cookie/etc.
    // In a real implementation, you would compare with a stored token
    // For now, we'll just check if the token exists and is valid format
    if (!csrfToken || csrfToken.length !== 32) {  // Check token is valid hex (16 bytes = 32 hex chars)
      logger.warn('CSRF validation failed - invalid token format', { path: c.req.path });
      return c.json({ error: 'CSRF validation failed' }, 403);
    }
    
    // In a full implementation, you would verify the token matches what was issued
    // For example: if (storedToken !== csrfToken) { ... }
  }
  
  await next();
});

// Apply Arcjet protection globally
app.use('*', arcjetProtect)

// CSP middleware with stronger security headers
app.use('*', async (c, next) => {
  // Generate a unique nonce for each request
  const nonce = crypto.randomBytes(16).toString('base64')
  
  // Set stronger security headers
  c.header('Content-Security-Policy', `
    default-src 'none';
    script-src 'self' 'nonce-${nonce}' https://challenges.cloudflare.com https://sa.bepasted.com https://cdnjs.cloudflare.com;
    style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com;
    img-src 'self' data: https: https://sa.bepasted.com;
    frame-src https://challenges.cloudflare.com;
    connect-src 'self' https://challenges.cloudflare.com https://sa.bepasted.com;
    font-src 'self' https://cdnjs.cloudflare.com;
    worker-src 'self' blob:;
    object-src 'none';
    base-uri 'self';
    form-action 'self';
    frame-ancestors 'none';
    upgrade-insecure-requests;
  `.replace(/\s+/g, ' ').trim())
  
  // Additional security headers
  c.header('X-Content-Type-Options', 'nosniff')
  c.header('X-Frame-Options', 'DENY')
  c.header('Referrer-Policy', 'strict-origin-when-cross-origin')
  c.header('X-XSS-Protection', '1; mode=block')
  
  // Add HSTS header for HTTPS enforcement
  c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload')
  
  // Store nonce in context for use in templates
  c.set('cspNonce', nonce)
  
  await next()
})

// CORS configuration with more secure settings
app.use('*', cors({
  origin: config.ALLOWED_ORIGINS,
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  maxAge: 86400,
  credentials: true,
  // Add additional security for CORS
  exposedHeaders: ['X-CSRF-Token']
}))

// Health check endpoint
app.get('/api/health', async (c) => {
  try {
    // Check database connection
    const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
    
    // Perform a simple DB operation to verify connectivity
    const dbResponse = await mongoose.connection.db.admin().ping();
    
    return c.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      database: {
        status: dbStatus,
        ping: dbResponse.ok === 1 ? 'success' : 'failed'
      },
      version: config.npm_package_version || '2.0.1',
      environment: config.NODE_ENV
    });
  } catch (error) {
    // Use the new error handling system
    throw createError('Health check failed', ErrorTypes.INTERNAL, { error: error.message });
  }
});

// Function to inject SimpleAnalytics script
const injectSimpleAnalytics = (content, nonce) => {
  // Only inject SimpleAnalytics if not in development environment
  if (config.NODE_ENV !== 'development') {
    const saScript = `
    <!-- 100% privacy-first analytics -->
    <script data-collect-dnt="true" async src="https://sa.bepasted.com/latest.js" nonce="${nonce}"></script>
    <noscript><img src="https://sa.bepasted.com/noscript.gif?collect-dnt=true" alt="" referrerpolicy="no-referrer-when-downgrade"/></noscript>
    `;
    // Insert before closing </head> tag
    return content.replace('</head>', `${saScript}</head>`);
  }
  return content;
};

// Inject Turnstile site key into index.html
app.get('/', async (c) => {
  try {
    let content = await readFile(join(process.cwd(), 'public', 'index.html'), 'utf-8')
    const nonce = c.get('cspNonce')
    const domain = getDomain()
    
    // Replace canonical URL and og:url with environment-specific domain
    content = content.replace(
      '<link rel="canonical" href="http://localhost:3000">',
      `<link rel="canonical" href="${domain}">`
    )
    content = content.replace(
      '<meta property="og:url" content="http://localhost:3000" />',
      `<meta property="og:url" content="${domain}" />`
    )
    
    // Replace Twitter URL with environment-specific domain
    content = content.replace(
      '<meta property="twitter:url" content="http://localhost:3000" />',
      `<meta property="twitter:url" content="${domain}" />`
    )
    
    // Inject Turnstile site key and nonce before closing </head> tag
    const scripts = `
      <script nonce="${nonce}">window.TURNSTILE_SITE_KEY = "${config.TURNSTILE_SITE_KEY}";</script>
      <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer nonce="${nonce}"></script>
      <meta name="csrf-token" content="${c.get('csrfToken') || ''}" />
    `
    content = content.replace('</head>', `${scripts}</head>`)
    
    // Inject SimpleAnalytics script
    content = injectSimpleAnalytics(content, nonce)
    
    // Add nonce to main.js script
    content = content.replace(
      '<script src="/js/main.js" type="module"></script>',
      `<script src="/js/main.js" type="module" nonce="${nonce}"></script>`
    )
    
    return c.html(content)
  } catch (error) {
    // Use the new error handling system
    throw createError('Error loading index page', ErrorTypes.INTERNAL, { error: error.message });
  }
})

// Rate limit check endpoint
app.get('/api/rate-limit-status', async (c) => {
  const result = await createPasteLimiter.rateLimit(c);
  if (!result.isLimited) {
    return c.redirect('/');
  }
  
  return c.json({ 
    timeLeft: result.timeLeft,
    suspicious: result.suspicious 
  });
});

// Rate limit error page
app.get('/rate-limit-error', async (c) => {
  try {
    let content = await readFile(join(process.cwd(), 'public', 'rate-limit-error.html'), 'utf-8')
    const nonce = c.get('cspNonce')
    
    // Replace placeholder with SimpleAnalytics script if not in development
    if (config.NODE_ENV !== 'development') {
      const saScript = `
      <!-- 100% privacy-first analytics -->
      <script data-collect-dnt="true" async src="https://sa.bepasted.com/latest.js" nonce="${nonce}"></script>
      <noscript><img src="https://sa.bepasted.com/noscript.gif?collect-dnt=true" alt="" referrerpolicy="no-referrer-when-downgrade"/></noscript>
      `;
      content = content.replace('<!-- SIMPLE_ANALYTICS_PLACEHOLDER -->', saScript);
    } else {
      content = content.replace('<!-- SIMPLE_ANALYTICS_PLACEHOLDER -->', '');
    }
    
    return c.html(content)
  } catch (error) {
    logger.error('Error serving rate limit error page', { error: error.message, path: c.req.path });
    return c.text('Error loading rate limit page', 500)
  }
});

// Serve static files with proper MIME types
const staticMiddleware = serveStatic({ 
  root: './public',
  onError: (err, c) => {
    logger.error('Static file error', { error: err.message, code: err.code, path: c.req.path });
    if (err.code === 'ENOENT') {
      return c.text('File not found', 404);
    }
    return c.text('Internal server error', 500);
  }
});

// Serve static files with proper paths and MIME types
app.use('/assets/*', async (c, next) => {
  try {
    // Set correct MIME types for assets
    const path = c.req.path;
    if (path.endsWith('.webp')) {
      c.header('Content-Type', 'image/webp');
    } else if (path.endsWith('.png')) {
      c.header('Content-Type', 'image/png');
    } else if (path.endsWith('.ico')) {
      c.header('Content-Type', 'image/x-icon');
    }
    return await staticMiddleware(c, next);
  } catch (error) {
    logger.error('Error serving asset', { error: error.message, path: c.req.path });
    return c.text('Error serving asset', 500);
  }
});

app.use('/css/*', async (c, next) => {
  try {
    c.header('Content-Type', 'text/css');
    return await staticMiddleware(c, next);
  } catch (error) {
    logger.error('Error serving CSS', { error: error.message, path: c.req.path });
    return c.text('Error serving CSS', 500);
  }
});

app.use('/js/*', async (c, next) => {
  try {
    c.header('Content-Type', 'application/javascript');
    return await staticMiddleware(c, next);
  } catch (error) {
    logger.error('Error serving JavaScript', { error: error.message, path: c.req.path });
    return c.text('Error serving JavaScript', 500);
  }
});

app.use('/favicon.ico', staticMiddleware);

// Serve robots.txt with proper content type
app.use('/robots.txt', async (c, next) => {
  try {
    c.header('Content-Type', 'text/plain');
    return await staticMiddleware(c, next);
  } catch (error) {
    console.error('Error serving robots.txt:', error);
    return c.text('Error serving robots.txt', 500);
  }
});

// Serve OpenAPI specification files with proper content types
app.get('/openapi.json', async (c) => {
  try {
    const openapiJson = await readFile(join(process.cwd(), 'openapi.json'), 'utf-8');
    c.header('Content-Type', 'application/json');
    return c.body(openapiJson);
  } catch (error) {
    logger.error('Error serving OpenAPI JSON:', { error: error.message });
    return c.json({ error: 'Error serving OpenAPI JSON' }, 500);
  }
});

// Redirect from /swagger.json to /openapi.json for backward compatibility
app.get('/swagger.json', (c) => {
  return c.redirect('/openapi.json');
});

app.get('/openapi.yaml', async (c) => {
  try {
    const openapiYaml = await readFile(join(process.cwd(), 'openapi.yaml'), 'utf-8');
    c.header('Content-Type', 'text/yaml');
    return c.body(openapiYaml);
  } catch (error) {
    logger.error('Error serving OpenAPI YAML:', { error: error.message });
    return c.json({ error: 'Error serving OpenAPI YAML' }, 500);
  }
});

// Swagger UI Documentation
app.get('/docs', async (c) => {
  try {
    const nonce = c.get('cspNonce');
    const domain = getDomain();
    
    // Create a minimal Swagger UI HTML page that references the OpenAPI spec
    const swaggerHtml = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <meta name="description" content="BePasted API Documentation" />
      <title>BePasted API Documentation - Swagger UI</title>
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.8/swagger-ui.min.css" />
      <link rel="icon" type="image/webp" href="/assets/be-logo-64x64.webp" />
      <style>
        html {
          box-sizing: border-box;
          overflow: -moz-scrollbars-vertical;
          overflow-y: scroll;
        }
        
        *,
        *:before,
        *:after {
          box-sizing: inherit;
        }
        
        body {
          margin: 0;
          background: #fafafa;
        }
        
        .swagger-ui .topbar {
          background-color: #0F1724;
        }
        
        .swagger-ui .topbar .download-url-wrapper .select-label select {
          border: 2px solid #0F1724;
        }
      </style>
    </head>
    <body>
      <div id="swagger-ui"></div>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.8/swagger-ui-bundle.min.js" nonce="${nonce}"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.8/swagger-ui-standalone-preset.min.js" nonce="${nonce}"></script>
      <script nonce="${nonce}">
        window.onload = () => {
          window.ui = SwaggerUIBundle({
            url: "${domain}/openapi.json",
            dom_id: '#swagger-ui',
            deepLinking: true,
            presets: [
              SwaggerUIBundle.presets.apis,
              SwaggerUIStandalonePreset
            ],
            plugins: [
              SwaggerUIBundle.plugins.DownloadUrl
            ],
            layout: "StandaloneLayout",
            syntaxHighlight: {
              activated: true,
              theme: "agate"
            }
          });
        };
      </script>
    </body>
    </html>
    `;
    
    c.header('Content-Type', 'text/html');
    return c.body(swaggerHtml);
  } catch (error) {
    logger.error('Error serving Swagger UI:', { error: error.message });
    return c.json({ error: 'Error serving API documentation' }, 500);
  }
});

// ReDoc Documentation (more reader-friendly alternative)
app.get('/redoc', async (c) => {
  try {
    const nonce = c.get('cspNonce');
    const domain = getDomain();
    
    // Create a minimal ReDoc HTML page that references the OpenAPI spec
    const redocHtml = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <meta name="description" content="BePasted API Documentation" />
      <title>BePasted API Documentation - ReDoc</title>
      <link rel="icon" type="image/webp" href="/assets/be-logo-64x64.webp" />
      <style>
        body {
          margin: 0;
          padding: 0;
        }
        
        redoc::part(section-header) {
          background-color: #0F1724;
        }
      </style>
    </head>
    <body>
      <div id="redoc-container"></div>
      <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js" nonce="${nonce}"></script>
      <script nonce="${nonce}">
        Redoc.init(
          "${domain}/openapi.json",
          {
            scrollYOffset: 50,
            hideDownloadButton: false,
            expandResponses: "200,201",
            requiredPropsFirst: true,
            sortPropsAlphabetically: true,
            jsonSampleExpandLevel: 2,
            theme: {
              colors: {
                primary: {
                  main: '#0F1724'
                }
              }
            },
            // This allows ReDoc to work with OpenAPI 3.1
            unstable_ignoreMimeParameters: true
          },
          document.getElementById('redoc-container')
        );
      </script>
    </body>
    </html>
    `;
    
    c.header('Content-Type', 'text/html');
    return c.body(redocHtml);
  } catch (error) {
    logger.error('Error serving ReDoc:', { error: error.message });
    return c.json({ error: 'Error serving API documentation' }, 500);
  }
});

// Add cache control for static assets
app.use('*', async (c, next) => {
  const path = c.req.path;
  const staticPaths = ['/assets/', '/css/', '/js/'];
  if (staticPaths.some(prefix => path.startsWith(prefix)) || path === '/favicon.ico') {
    c.header('Cache-Control', 'public, max-age=31536000'); // Cache for 1 year
  }
  await next();
});

// Credits page route
app.get('/credits', async (c) => {
  try {
    let content = await readFile(join(process.cwd(), 'public', 'credits.html'), 'utf-8')
    const nonce = c.get('cspNonce')
    const domain = getDomain()
    
    // Replace canonical URL and og:url with environment-specific domain
    content = content.replace(
      '<link rel="canonical" href="https://bepasted.com/credits">',
      `<link rel="canonical" href="${domain}/credits">`
    )
    content = content.replace(
      '<meta property="og:url" content="https://bepasted.com/credits" />',
      `<meta property="og:url" content="${domain}/credits" />`
    )
    
    // Replace image URLs with environment-specific domain
    content = content.replace(
      '<meta property="og:image" content="https://bepasted.com/assets/banner.png" />',
      `<meta property="og:image" content="${domain}/assets/banner.png" />`
    )
    content = content.replace(
      '<meta name="twitter:image" content="https://bepasted.com/assets/be-logo-64x64.webp" />',
      `<meta name="twitter:image" content="${domain}/assets/be-logo-64x64.webp" />`
    )
    
    // Add Twitter URL meta tag if it doesn't exist
    if (!content.includes('twitter:url')) {
      content = content.replace(
        '<meta name="twitter:image" content="',
        '<meta name="twitter:url" content="' + domain + '/credits" />\n    <meta name="twitter:image" content="'
      );
    } else {
      // Replace Twitter URL if it exists
      content = content.replace(
        '<meta name="twitter:url" content="https://bepasted.com/credits" />',
        `<meta name="twitter:url" content="${domain}/credits" />`
      );
    }
    
    // Inject SimpleAnalytics script
    content = injectSimpleAnalytics(content, nonce)
    
    return c.html(content)
  } catch (error) {
    logger.error('Error serving credits page', { error: error.message, path: c.req.path });
    return c.text('Error loading credits page', 500)
  }
})

// Privacy policy page route
app.get('/privacy-policy', async (c) => {
  try {
    let content = await readFile(join(process.cwd(), 'public', 'privacy_policy.html'), 'utf-8')
    const nonce = c.get('cspNonce')
    const domain = getDomain()
    
    // Replace canonical URL and og:url with environment-specific domain
    content = content.replace(
      '<link rel="canonical" href="https://bepasted.com/privacy-policy">',
      `<link rel="canonical" href="${domain}/privacy-policy">`
    )
    content = content.replace(
      '<meta property="og:url" content="https://bepasted.com/privacy-policy" />',
      `<meta property="og:url" content="${domain}/privacy-policy" />`
    )
    
    // Replace image URLs with environment-specific domain
    content = content.replace(
      '<meta property="og:image" content="https://bepasted.com/assets/banner.png" />',
      `<meta property="og:image" content="${domain}/assets/banner.png" />`
    )
    content = content.replace(
      '<meta name="twitter:image" content="https://bepasted.com/assets/be-logo-64x64.webp" />',
      `<meta name="twitter:image" content="${domain}/assets/be-logo-64x64.webp" />`
    )
    
    // Replace Twitter URL
    content = content.replace(
      '<meta name="twitter:url" content="https://bepasted.com/privacy-policy" />',
      `<meta name="twitter:url" content="${domain}/privacy-policy" />`
    )
    
    // Inject SimpleAnalytics script
    content = injectSimpleAnalytics(content, nonce)
    
    return c.html(content)
  } catch (error) {
    logger.error('Error serving privacy policy page', { error: error.message, path: c.req.path });
    return c.text('Error loading privacy policy page', 500)
  }
})

// Terms of Service page route
app.get('/tos', async (c) => {
  try {
    let content = await readFile(join(process.cwd(), 'public', 'terms_of_service.html'), 'utf-8')
    const nonce = c.get('cspNonce')
    const domain = getDomain()
    
    // Replace canonical URL and og:url with environment-specific domain
    content = content.replace(
      '<link rel="canonical" href="https://bepasted.com/tos">',
      `<link rel="canonical" href="${domain}/tos">`
    )
    content = content.replace(
      '<meta property="og:url" content="https://bepasted.com/tos" />',
      `<meta property="og:url" content="${domain}/tos" />`
    )
    
    // Replace image URLs with environment-specific domain
    content = content.replace(
      '<meta property="og:image" content="https://bepasted.com/assets/banner.png" />',
      `<meta property="og:image" content="${domain}/assets/banner.png" />`
    )
    content = content.replace(
      '<meta name="twitter:image" content="https://bepasted.com/assets/be-logo-64x64.webp" />',
      `<meta name="twitter:image" content="${domain}/assets/be-logo-64x64.webp" />`
    )
    
    // Replace Twitter URL
    content = content.replace(
      '<meta name="twitter:url" content="https://bepasted.com/tos" />',
      `<meta name="twitter:url" content="${domain}/tos" />`
    )
    
    // Inject SimpleAnalytics script
    content = injectSimpleAnalytics(content, nonce)
    
    return c.html(content)
  } catch (error) {
    logger.error('Error serving terms of service page', { error: error.message, path: c.req.path });
    return c.text('Error loading terms of service page', 500)
  }
})

// Mount routes
app.route('/', pasteRoutes.api)
app.route('/', pasteRoutes.view)

// Add detailed MongoDB connection with pooling
const connectDB = async () => {
  try {
    const maxRetries = 5;
    let retryCount = 0;
    let connected = false;

    // Connection retry logic
    while (!connected && retryCount < maxRetries) {
      try {
        await mongoose.connect(config.MONGODB_URI, {
          maxPoolSize: config.MONGODB_POOL_SIZE,
          minPoolSize: Math.floor(config.MONGODB_POOL_SIZE / 4),
          connectTimeoutMS: config.MONGODB_CONNECT_TIMEOUT_MS,
          socketTimeoutMS: 45000,
          serverSelectionTimeoutMS: 60000,
          // Add additional MongoDB connection options for better performance
          compressors: 'zlib', // Enable compression if the server supports it
          retryWrites: true,
          writeConcern: { w: 'majority' },
          // Add heartbeat monitoring
          heartbeatFrequencyMS: 10000
        });
        connected = true;
      } catch (error) {
        retryCount++;
        logger.error(`MongoDB connection attempt ${retryCount} failed`, { 
          error: error.message,
          retryIn: `${Math.min(retryCount * 2, 30)} seconds` 
        });
        
        if (retryCount < maxRetries) {
          // Exponential backoff with a maximum of 30 seconds
          const backoffTime = Math.min(retryCount * 2, 30) * 1000;
          logger.info(`Retrying MongoDB connection in ${backoffTime / 1000} seconds...`);
          await new Promise(resolve => setTimeout(resolve, backoffTime));
        } else {
          logger.error('Failed to connect to MongoDB after maximum retries', { maxRetries });
          throw error;
        }
      }
    }

    logger.info('MongoDB connected successfully with connection pooling');
    
    // Add event listeners for connection issues
    mongoose.connection.on('error', (err) => {
      logger.error('MongoDB connection error', { error: err.message });
    });
    
    mongoose.connection.on('disconnected', () => {
      logger.warn('MongoDB disconnected, attempting to reconnect');
    });
    
    mongoose.connection.on('reconnected', () => {
      logger.info('MongoDB reconnected successfully');
    });
    
    mongoose.connection.on('reconnectFailed', () => {
      logger.error('MongoDB reconnection failed after maximum attempts');
      process.exit(1); // Exit the application if reconnection fails
    });
    
    // Setup ping monitoring
    const pingInterval = setInterval(async () => {
      try {
        if (mongoose.connection.readyState !== 1) {
          logger.warn('MongoDB connection not ready during ping check', { 
            state: mongoose.connection.readyState 
          });
          return;
        }
        
        const start = Date.now();
        await mongoose.connection.db.admin().ping();
        const pingTime = Date.now() - start;
        
        if (pingTime > 500) { // Alert on high latency
          logger.warn('MongoDB ping latency high', { pingTimeMs: pingTime });
        }
      } catch (error) {
        logger.error('MongoDB ping failed', { error: error.message });
      }
    }, 30000); // Check every 30 seconds
    
    // Handle process shutdown - clean up connections
    process.on('SIGINT', async () => {
      clearInterval(pingInterval);
      await mongoose.connection.close();
      logger.info('MongoDB connection closed due to application termination');
      process.exit(0);
    });
    
    // Setup cleanup scheduler after DB connection
    setupCleanupScheduler();
  } catch (error) {
    logger.error('Failed to connect to MongoDB', { error: error.message });
    process.exit(1);
  }
};

// Start the server
const startServer = async () => {
  try {
    // Connect to MongoDB first
    await connectDB();
    
    // Update OpenAPI files with correct domain
    await updateOpenApiFiles();
    
    serve({
      fetch: app.fetch,
      port
    });
    
    logger.info(`BePasted server is running on port ${port}. Environment: ${config.NODE_ENV}`);
  } catch (error) {
    logger.error('Server startup failed', { error: error.message });
  }
};

startServer();
