export interface RoleConfig {
  roles: string[];
  defaultRole?: string;
  adminRole?: string;
  superAdminRole?: string;
}

export interface AuthRoleProvider {
  getRoleConfig(): RoleConfig;
}
