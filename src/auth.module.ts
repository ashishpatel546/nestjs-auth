import { DataSource } from "typeorm";
import { User } from "./entity/user.entity";
import { DynamicModule } from "@nestjs/common";
import { JwtModule } from "@nestjs/jwt";
import { AuthService } from "./auth/auth.service";

export interface JwtConfigOptions {
  secret: string;
  expiresIn: string;
  issuer?: string;
}

export class AuthModule {
  static forExistingConnection(
    dataSource: DataSource | string,
    jwtConfig: JwtConfigOptions
  ): DynamicModule {
    if (!jwtConfig?.secret) {
      throw new Error('JWT secret is required');
    }

    return {
      module: AuthModule,
      imports: [
        JwtModule.register({
          secret: jwtConfig.secret,
          signOptions: {
            expiresIn: jwtConfig.expiresIn,
            issuer: jwtConfig.issuer,
          },
        }),
      ],
      providers: [
        {
          provide: 'USER_REPOSITORY',
          useFactory: (ds: DataSource) => ds.getRepository(User),
          inject: [typeof dataSource === 'string' ? dataSource : DataSource],
        },
        {
          provide: 'JWT_CONFIG',
          useValue: jwtConfig,
        },
        AuthService,
      ],
      exports: [AuthService],
    };
  }
}
