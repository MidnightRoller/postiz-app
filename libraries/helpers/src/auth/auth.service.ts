import { sign, verify } from 'jsonwebtoken';
import { hashSync, compareSync } from 'bcrypt';
import crypto from 'crypto';

export class AuthService {
  static hashPassword(password: string) {
    return hashSync(password, 10);
  }

  static comparePassword(password: string, hash: string) {
    return compareSync(password, hash);
  }

  static signJWT(value: object) {
    return sign(value, process.env.JWT_SECRET!);
  }

  static verifyJWT(token: string) {
    return verify(token, process.env.JWT_SECRET!);
  }

  static fixedEncryption(value: string) {
    const algorithm = 'aes-256-cbc';
    
    // Create a key from JWT_SECRET (32 bytes for aes-256)
    // scryptSync already returns a Buffer
    const key = crypto.scryptSync(process.env.JWT_SECRET!, 'salt', 32);
    
    // Generate a random initialization vector (16 bytes for AES)
    // randomBytes already returns a Buffer
    const iv = crypto.randomBytes(16);
    
    // Create cipher with key and IV
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    
    // Encrypt the plain text
    let encrypted = cipher.update(value, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // Return IV + encrypted data (IV is needed for decryption)
    return iv.toString('hex') + ':' + encrypted;
  }

  static fixedDecryption(hash: string) {
    const algorithm = 'aes-256-cbc';
    
    // Create the same key from JWT_SECRET
    // scryptSync already returns a Buffer
    const key = crypto.scryptSync(process.env.JWT_SECRET!, 'salt', 32);
    
    // Split the IV and encrypted data
    const parts = hash.split(':');
    if (parts.length !== 2) {
      throw new Error('Invalid hash format');
    }
    const iv = Buffer.from(parts[0], 'hex');
    const encryptedText = parts[1];
    
    // Create decipher with key and IV
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    
    // Decrypt the encrypted text
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
}