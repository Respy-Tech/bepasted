# Script to generate secure random strings for BePasted .env file

# Function to generate a secure random string
function Generate-RandomString {
    param(
        [int]$Length = 64
    )
    
    $CharSet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&()*+,-./:;<=>?@[\]^_`{|}~'
    $SecureString = ""
    $Rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    
    for ($i = 0; $i -lt $Length; $i++) {
        $Byte = New-Object Byte[]([System.Math]::Ceiling($Length/8)*8)
        $Rng.GetBytes($Byte)
        $Index = $Byte[$i] % $CharSet.Length
        $SecureString += $CharSet[$Index]
    }
    
    return $SecureString
}

# Generate secure random values
$IP_HASH_SALT = Generate-RandomString -Length 64
$CSRF_SECRET = Generate-RandomString -Length 64

# Output the values in .env format
Write-Host "# Generated secure values for BePasted"
Write-Host "IP_HASH_SALT=$IP_HASH_SALT"
Write-Host "CSRF_SECRET=$CSRF_SECRET"
Write-Host ""
Write-Host "# Copy these values to your .env file" 