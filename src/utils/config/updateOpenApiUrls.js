/**
 * Utility to update OpenAPI documentation URLs based on environment
 */
import { readFile, writeFile } from 'fs/promises';
import { join } from 'path';
import { getDomain } from './domain.js';
import logger from '../logging/logger.js';

/**
 * Updates the OpenAPI YAML file with the correct domain based on environment
 */
export async function updateOpenApiYaml() {
  try {
    const domain = getDomain();
    const filePath = join(process.cwd(), 'openapi.yaml');
    let content = await readFile(filePath, 'utf-8');
    
    // Update the first server URL (production) with current domain if in development
    if (domain.includes('localhost')) {
      content = content.replace(
        /servers:\n\s+- url: https:\/\/bepasted\.com/,
        `servers:\n  - url: ${domain}`
      );
    }
    
    await writeFile(filePath, content, 'utf-8');
    logger.info('OpenAPI YAML file updated with correct domain');
  } catch (error) {
    logger.error('Error updating OpenAPI YAML file', { error: error.message });
  }
}

/**
 * Updates the OpenAPI JSON file with the correct domain based on environment
 */
export async function updateOpenApiJson() {
  try {
    const domain = getDomain();
    const filePath = join(process.cwd(), 'openapi.json');
    let content = await readFile(filePath, 'utf-8');
    
    // Parse JSON to update the server URL
    const openApiDoc = JSON.parse(content);
    
    // Update the first server URL (production) with current domain if in development
    if (domain.includes('localhost')) {
      if (openApiDoc.servers && openApiDoc.servers.length > 0) {
        openApiDoc.servers[0].url = domain;
      }
      
      // Update the content with the modified JSON
      content = JSON.stringify(openApiDoc, null, 2);
      await writeFile(filePath, content, 'utf-8');
    }
    
    logger.info('OpenAPI JSON file updated with correct domain');
  } catch (error) {
    logger.error('Error updating OpenAPI JSON file', { error: error.message });
  }
}

/**
 * Updates both OpenAPI specification files
 */
export async function updateOpenApiFiles() {
  await updateOpenApiYaml();
  await updateOpenApiJson();
} 