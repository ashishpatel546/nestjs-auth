import {
  Injectable,
  Logger,
  UnauthorizedException,
  InternalServerErrorException,
  ConflictException,
  NotFoundException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Repository, EntityManager } from 'typeorm';
import { User, USER_ROLE } from '../entity/user.entity';
import * as bcrypt from 'bcrypt';
import { JwtConfigOptions } from './interfaces/jwt-config.interface';
import { ValidationResult } from './interfaces/validation-result.interface';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { PasswordResetResult } from './interfaces/password-reset-result.interface';
import { instanceToPlain } from 'class-transformer';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly userRepository: Repository<User>,
    private readonly jwtService: JwtService,
    private readonly jwtConfig: JwtConfigOptions,
    private readonly entityManager: EntityManager
  ) {
    this.logger.log('AuthService initialized');
  }

  private async isSuperAdminExists(): Promise<boolean> {
    try {
      const superAdmin = await this.entityManager.query(
        'SELECT * FROM "user" WHERE "role" = $1',
        [USER_ROLE.SUPER_ADMIN]
      );
      return superAdmin.length > 0;
    } catch (error) {
      this.logger.error('Error checking if super admin exists');
      this.logger.error(`Cause: ${error.message}`);
      throw new InternalServerErrorException(
        'Error checking if super admin exists'
      );
    }
  }

  async validateUser(
    email: string,
    password: string
  ): Promise<ValidationResult> {
    try {
      const users = await this.entityManager.query(
        'SELECT * FROM "user" WHERE email = $1',
        [email]
      );
      const user = users[0];
      
      if (user && (await bcrypt.compare(password, user.password))) {
        const token = await this.generateToken(user);
        return {
          isValidated: true,
          userRole: user.role,
          token,
          user: instanceToPlain(user) as User,
        };
      }
      return {
        isValidated: false,
      };
    } catch (error) {
      this.logger.error('Error validating user credentials');
      this.logger.error(`Cause: ${error.message}`);
      throw new InternalServerErrorException('Error validating user');
    }
  }

  private async generateToken(user: User): Promise<string> {
    const payload: JwtPayload = {
      email: user.email,
      role: user.role,
    };
    return this.jwtService.signAsync(payload);
  }

  async validateToken(token: string): Promise<User> {
    try {
      const payload = await this.jwtService.verifyAsync<JwtPayload>(token, {
        secret: this.jwtConfig.secret,
      });

      const users = await this.entityManager.query(
        'SELECT * FROM "user" WHERE email = $1',
        [payload.email]
      );
      const user = users[0];

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      return user;
    } catch (error) {
      this.logger.error('Error validating JWT token');
      this.logger.error(`Cause: ${error.message}`);
      throw new UnauthorizedException('Invalid token');
    }
  }

  async validateUserFromJWT(token: string): Promise<ValidationResult> {
    try {
      const user = await this.validateToken(token);

      if (!user.is_active) {
        return {
          isValidated: false,
        };
      }

      return {
        isValidated: true,
        userRole: user.role,
        user: instanceToPlain(user) as User,
      };
    } catch (error) {
      this.logger.error('Error validating user from JWT token');
      this.logger.error(`Cause: ${error.message}`);
      return {
        isValidated: false,
      };
    }
  }

  async registerUser(
    email: string,
    password: string,
    role: USER_ROLE = USER_ROLE.TECH_ROLE,
    firstName?: string,
    lastName?: string,
    mobile?: string
  ): Promise<User> {
    try {
      this.logger.log(
        `Attempting to register user with email: ${email} and role: ${role}`
      );
      const existingUser = await this.entityManager.query(
        'SELECT * FROM "user" WHERE email = $1',
        [email]
      );

      if (existingUser.length > 0) {
        this.logger.warn(
          `Registration failed: User with email ${email} already exists`
        );
        throw new ConflictException('User with this email already exists.');
      }

      if (role === USER_ROLE.SUPER_ADMIN) {
        this.logger.log('Redirecting to super admin registration');
        return this.registerSuperAdmin(
          email,
          password,
          firstName,
          lastName,
          mobile
        );
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = this.userRepository.create({
        email,
        password: hashedPassword,
        first_name: firstName,
        last_name: lastName,
        created_on: new Date(),
        updated_on: new Date(),
        role: role,
        mobile,
        is_active: false, // Always false for non-super admin users
      });
      this.logger.log(`Successfully registered user with email: ${email}`);
      return this.userRepository.save(newUser);
    } catch (error) {
      this.logger.error('Error registering new user');
      this.logger.error(`Cause: ${error.message}`);
      throw new InternalServerErrorException('Error registering user');
    }
  }

  async registerSuperAdmin(
    email: string,
    password: string,
    firstName?: string,
    lastName?: string,
    mobile?: string
  ): Promise<User> {
    try {
      this.logger.log(
        `Attempting to register super admin with email: ${email}`
      );

      const superAdminExists = await this.isSuperAdminExists();
      if (superAdminExists) {
        this.logger.warn(
          'Super admin registration failed: Super admin already exists'
        );
        throw new ConflictException(
          'Super Admin already exists. Cannot register another Super Admin.'
        );
      }

      const existingUser = await this.entityManager.query(
        'SELECT * FROM "user" WHERE email = $1',
        [email]
      );
      if (existingUser.length > 0) {
        this.logger.warn(
          `Super admin registration failed: Email ${email} already exists`
        );
        throw new ConflictException('User with this email already exists.');
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = this.userRepository.create({
        email,
        password: hashedPassword,
        first_name: firstName,
        last_name: lastName,
        created_on: new Date(),
        updated_on: new Date(),
        role: USER_ROLE.SUPER_ADMIN,
        mobile,
        is_active: true,
      });

      this.logger.log(
        `Successfully registered super admin with email: ${email}`
      );
      return this.userRepository.save(newUser);
    } catch (error) {
      this.logger.error('Error registering super admin');
      this.logger.error(`Cause: ${error.message}`);
      throw new InternalServerErrorException('Error registering super admin');
    }
  }

  async activateUser(
    userEmail: string,
    adminEmail: string,
    adminPassword: string
  ): Promise<User> {
    try {
      // First validate admin credentials
      const validation = await this.validateUser(adminEmail, adminPassword);
      if (!validation.isValidated) {
        throw new UnauthorizedException('Invalid admin credentials');
      }

      // Check if the validated user has admin privileges
      if (
        ![USER_ROLE.ADMIN, USER_ROLE.SUPER_ADMIN].includes(validation.userRole)
      ) {
        throw new UnauthorizedException(
          'Unauthorized: Only administrators can activate users'
        );
      }

      const users = await this.entityManager.query(
        'SELECT * FROM "user" WHERE email = $1',
        [userEmail]
      );
      const user = users[0];
      
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      await this.entityManager.query(
        'UPDATE "user" SET is_active = true, updated_on = $1 WHERE email = $2',
        [new Date(), userEmail]
      );

      return { ...user, is_active: true, updated_on: new Date() };
    } catch (error) {
      this.logger.error('Error activating user');
      this.logger.error(`Cause: ${error.message}`);
      throw new InternalServerErrorException('Error activating user');
    }
  }

  async activateUserWithToken(adminToken: string, userEmail: string): Promise<User> {
    try {
      // Validate admin token and check role
      const admin = await this.validateToken(adminToken);
      if (admin.role !== USER_ROLE.SUPER_ADMIN) {
        throw new UnauthorizedException('Only super admins can activate users');
      }

      const users = await this.entityManager.query(
        'SELECT * FROM "user" WHERE email = $1',
        [userEmail]
      );
      const user = users[0];
      
      if (!user) {
        throw new NotFoundException('User not found');
      }

      await this.entityManager.query(
        'UPDATE "user" SET is_active = true, updated_on = $1 WHERE email = $2',
        [new Date(), userEmail]
      );

      this.logger.log(`User ${userEmail} activated by super admin: ${admin.email}`);
      return { ...user, is_active: true, updated_on: new Date() };
    } catch (error) {
      this.logger.error('Error activating user with token');
      this.logger.error(`Cause: ${error.message}`);
      throw new InternalServerErrorException('Error activating user');
    }
  }

  async changePassword(token: string, oldPassword: string, newPassword: string): Promise<boolean> {
    try {
      // Validate token and get user
      const user = await this.validateToken(token);
      
      // Verify old password
      const users = await this.entityManager.query(
        'SELECT * FROM "user" WHERE email = $1',
        [user.email]
      );
      const currentUser = users[0];
      
      if (!currentUser || !(await bcrypt.compare(oldPassword, currentUser.password))) {
        throw new UnauthorizedException('Current password is incorrect');
      }

      // Hash new password and update
      const hashedNewPassword = await bcrypt.hash(newPassword, 10);
      await this.entityManager.query(
        'UPDATE "user" SET password = $1, updated_on = $2 WHERE email = $3',
        [hashedNewPassword, new Date(), user.email]
      );

      this.logger.log(`Password successfully changed for user: ${user.email}`);
      return true;
    } catch (error) {
      this.logger.error('Error changing password');
      this.logger.error(`Cause: ${error.message}`);
      throw new InternalServerErrorException('Error changing password');
    }
  }

  async resetUserPassword(adminToken: string, userEmail: string): Promise<PasswordResetResult> {
    try {
      // Validate admin token and check role
      const admin = await this.validateToken(adminToken);
      if (admin.role !== USER_ROLE.SUPER_ADMIN) {
        throw new UnauthorizedException('Only super admins can reset passwords');
      }

      // Check if user exists
      const users = await this.entityManager.query(
        'SELECT * FROM "user" WHERE email = $1',
        [userEmail]
      );
      
      if (users.length === 0) {
        throw new NotFoundException('User not found');
      }

      // Generate random alphanumeric password (8 characters)
      const newPassword = Math.random().toString(36).slice(-8);
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      // Update password in database
      await this.entityManager.query(
        'UPDATE "user" SET password = $1, updated_on = $2 WHERE email = $3',
        [hashedPassword, new Date(), userEmail]
      );

      this.logger.log(`Password reset successful for user: ${userEmail}`);
      return {
        success: true,
        newPassword: newPassword,
        message: 'Password reset successful'
      };
    } catch (error) {
      this.logger.error('Error resetting password');
      this.logger.error(`Cause: ${error.message}`);
      return {
        success: false,
        message: error.message || 'Error resetting password'
      };
    }
  }
}
