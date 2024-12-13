
import { User, USER_ROLE } from '../../entity/user.entity';

export interface ValidationResult {
  isValidated: boolean;
  userRole?: USER_ROLE;
  token?: string;
  user?: User;
}