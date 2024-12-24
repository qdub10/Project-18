import { AuthenticationError } from 'apollo-server-express';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

interface JwtPayload {
  _id: string;
  username: string;
  email: string;
}

const secretKey = process.env.JWT_SECRET_KEY || '';

/**
 * Middleware function to extract and verify the JWT token for GraphQL context.
 * @param token - The JWT token passed in the Authorization header.
 * @returns - Decoded user data if the token is valid, otherwise throws an AuthenticationError.
 */
export const authenticateToken = (token: string | undefined): JwtPayload => {
  if (!token) {
    throw new AuthenticationError('Authorization token is required.');
  }

  try {
    // Remove the "Bearer " prefix if present
    const formattedToken = token.startsWith('Bearer ') ? token.split(' ')[1] : token;

    // Verify and decode the token
    const user = jwt.verify(formattedToken, secretKey) as JwtPayload;

    return user;
  } catch (err) {
    throw new AuthenticationError('Invalid or expired token.');
  }
};

/**
 * Function to generate a JWT token for the user.
 * @param username - The username of the user.
 * @param email - The email of the user.
 * @param _id - The user's unique ID.
 * @returns - A signed JWT token.
 */
export const signToken = (username: string, email: string, _id: string): string => {
  const payload = { username, email, _id };

  return jwt.sign(payload, secretKey, { expiresIn: '1h' });
};
