# NestJS Authentication Module

## Overview

This NestJS Authentication Module provides a robust, flexible authentication system with JWT-based authentication, user management, and role-based access control.

## Features

- JWT-based authentication
- Currently for SQL database
- User registration (with multiple roles)
- User activation by administrators
- Password management (change and reset)
- Super admin registration with strict controls
- Secure password hashing
- Role-based access control

## Installation

Install the package using npm:

```bash
npm install @your-org/nestjs-auth-module
```

## Configuration

### Module Setup

```typescript
import { AuthModule } from '@your-org/nestjs-auth-module';
import { CustomAuthConfigProvider } from './custom-auth-config.provider';

@Module({
  imports: [
    AuthModule.forExistingDataSource('default', {
      provide: 'AUTH_CONFIG_PROVIDER',
      useClass: CustomAuthConfigProvider
    })
  ]
})
export class AppModule {}
```

### Creating a Config Provider

```typescript
import { Injectable } from '@nestjs/common';
import { AuthConfigProvider } from '@your-org/nestjs-auth-module';

@Injectable()
export class CustomAuthConfigProvider implements AuthConfigProvider {
  getJwtConfig() {
    return {
      secret: process.env.JWT_SECRET,
      expiresIn: '1h',
      issuer: 'YourApp'
    };
  }
}
```

## Usage Examples

### User Registration

```typescript
@Injectable()
export class UserService {
  constructor(private authService: AuthService) {}

  async createUser() {
    // Register a new user with a specific role
    const user = await this.authService.registerUser(
      'user@example.com', 
      'password123', 
      USER_ROLE.TECH_ROLE
    );
  }

  async createSuperAdmin() {
    // Register a super admin (only one allowed)
    const superAdmin = await this.authService.registerSuperAdmin(
      'admin@example.com', 
      'securePassword'
    );
  }
}
```

### User Authentication

```typescript
@Injectable()
export class AuthController {
  constructor(private authService: AuthService) {}

  async login(email: string, password: string) {
    // Validate user credentials
    const result = await this.authService.validateUser(email, password);
    
    if (result.isValidated) {
      return {
        token: result.token,
        user: result.user
      };
    }
  }

  async validateToken(token: string) {
    // Validate an existing JWT token
    const validationResult = await this.authService.validateUserFromJWT(token);
    return validationResult.isValidated;
  }
}
```

### User Activation

```typescript
@Injectable()
export class AdminService {
  constructor(private authService: AuthService) {}

  async activateNewUser(userEmail: string) {
    // Activate a user (requires admin credentials)
    const activatedUser = await this.authService.activateUser(
      userEmail, 
      'admin@example.com', 
      'adminPassword'
    );
  }
}
```

### Password Management

```typescript
@Injectable()
export class UserManagementService {
  constructor(private authService: AuthService) {}

  async changeUserPassword(token: string) {
    // Change user's password
    await this.authService.changePassword(
      token, 
      'oldPassword', 
      'newPassword'
    );
  }

  async resetUserPassword(adminToken: string, userEmail: string) {
    // Super admin can reset user password
    const resetResult = await this.authService.resetUserPassword(
      adminToken, 
      userEmail
    );
    
    if (resetResult.success) {
      // Send new password to user
      console.log(resetResult.newPassword);
    }
  }
}
```

## User Roles

The module supports the following user roles:
- `SUPER_ADMIN`: Full system access
- `ADMIN`: Administrative privileges
- `TECH_ROLE`: Standard user role
- More roles can be added in the `USER_ROLE` enum

## Security Features

- Passwords are hashed using bcrypt
- JWT tokens with configurable expiration
- Role-based access control
- Only one super admin can be registered
- Users are inactive by default and require activation

## Error Handling

The module throws specific exceptions:
- `UnauthorizedException`
- `ConflictException`
- `InternalServerErrorException`
- `NotFoundException`

## Environment Variables

Recommended environment variables:
- `JWT_SECRET`: Secret key for JWT token generation
- `JWT_EXPIRES_IN`: Token expiration time

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

[Your License Here]

## Support

For support, please open an issue in the GitHub repository or contact [ashi.patel546@gmail.com].
