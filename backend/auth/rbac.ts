import { APIGatewayProxyEvent } from 'aws-lambda';

export type Role = 'admin' | 'operator' | 'viewer';

export interface AuthContext {
  userId: string;
  role: Role;
  userName: string;
}

export const ROLE_PERMISSIONS: Record<Role, Set<string>> = {
  admin: new Set([
    'users:read',
    'users:create',
    'users:update',
    'users:delete',
    'reports:read',
    'reports:create',
    'reports:update',
    'reports:delete',
    'report_items:read',
    'report_items:create',
    'report_items:update',
    'report_items:delete',
    'bulk:import',
    'audit:read',
  ]),
  operator: new Set([
    'users:read',
    'users:create',
    'users:update',
    'reports:read',
    'reports:create',
    'reports:update',
    'reports:delete',
    'report_items:read',
    'report_items:create',
    'report_items:update',
    'report_items:delete',
    'bulk:import',
  ]),
  viewer: new Set([
    'users:read',
    'reports:read',
    'report_items:read',
    'audit:read',
  ]),
};

export function extractAuthContext(event: APIGatewayProxyEvent): AuthContext {
  const authHeader = event.headers['Authorization'] || '';
  const token = authHeader.replace('Bearer ', '');
  
  // Mock authentication - in production, validate JWT
  const decoded = Buffer.from(token, 'base64').toString('utf-8');
  const [userId, role, userName] = decoded.split(':');
  
  return {
    userId: userId || 'unknown',
    role: (role as Role) || 'viewer',
    userName: userName || 'Unknown',
  };
}

export function hasPermission(role: Role, permission: string): boolean {
  return ROLE_PERMISSIONS[role]?.has(permission) ?? false;
}

export function requirePermission(role: Role, permission: string): void {
  if (!hasPermission(role, permission)) {
    throw new ForbiddenError(`Permission denied: ${permission}`);
  }
}

export class ForbiddenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ForbiddenError';
  }
}

export class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NotFoundError';
  }
}

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}