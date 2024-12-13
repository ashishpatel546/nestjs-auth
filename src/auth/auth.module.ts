import { Module, DynamicModule, Logger } from '@nestjs/common';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { DataSource, Repository, EntityManager } from 'typeorm';
import { getDataSourceToken, getEntityManagerToken } from '@nestjs/typeorm';
import { AuthService } from './auth.service';
import { User } from '../entity/user.entity';
import { JwtConfigOptions, AuthConfigProvider } from './interfaces/jwt-config.interface';

export const AUTH_CONFIG_PROVIDER = 'AUTH_CONFIG_PROVIDER';

@Module({})
export class AuthModule {
  static forExistingDataSource(
    connectionName: string,
    configProvider: {
      provide: string | symbol;
      useClass: new (...args: any[]) => AuthConfigProvider;
    }
  ): DynamicModule {
    const userRepositoryToken = `${connectionName || 'default'}_USER_REPOSITORY`;
    const entityManagerToken = getEntityManagerToken(connectionName);
    const logger = new Logger('AuthModule');

    // Create a config module that exports the provider
    const ConfigModule = {
      module: class ConfigModule {},
      providers: [configProvider],
      exports: [configProvider],
    };

    return {
      module: AuthModule,
      imports: [
        ConfigModule,
        JwtModule.registerAsync({
          imports: [ConfigModule],  // Import the config module here
          inject: [configProvider.provide],
          useFactory: (config: AuthConfigProvider) => ({
            secret: config.getJwtConfig().secret,
            signOptions: {
              expiresIn: config.getJwtConfig().expiresIn,
              issuer: config.getJwtConfig().issuer,
            },
          }),
        }),
      ],
      providers: [
        // First provide EntityManager
        {
          provide: entityManagerToken,
          useFactory: (dataSource: DataSource) => {
            logger.log(`Initializing EntityManager for connection: ${connectionName}`);
            return dataSource.manager;
          },
          inject: [getDataSourceToken(connectionName)],
        },
        // Then provide Repository
        {
          provide: userRepositoryToken,
          useFactory: (dataSource: DataSource) => {
            logger.log(`Initializing User Repository for connection: ${connectionName}`);
            return dataSource.getRepository(User);
          },
          inject: [getDataSourceToken(connectionName)],
        },
        // Finally provide AuthService with all its dependencies
        {
          provide: AuthService,
          useFactory: (
            userRepo: Repository<User>,
            jwtService: JwtService,
            config: AuthConfigProvider,
            entityManager: EntityManager
          ) => {
            logger.log('Initializing AuthService with dependencies');
            return new AuthService(
              userRepo,
              jwtService,
              config.getJwtConfig(),
              entityManager
            );
          },
          inject: [
            userRepositoryToken,
            JwtService,
            configProvider.provide,
            entityManagerToken,
          ],
        },
      ],
      exports: [AuthService],
    };
  }
}