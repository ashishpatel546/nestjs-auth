
import { USER_ROLE } from '../../entity/user.entity';

export interface JwtPayload {
  email: string;
  role: USER_ROLE;
}