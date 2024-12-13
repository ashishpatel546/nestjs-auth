
export interface JwtConfigOptions {
  secret: string;
  expiresIn?: string | number;
  issuer?: string;
}

export interface AuthConfigProvider {
  getJwtConfig(): JwtConfigOptions;
}