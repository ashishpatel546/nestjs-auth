import { Column, Entity, PrimaryColumn } from 'typeorm';
import { Exclude } from 'class-transformer';

export enum USER_ROLE {
  SUPER_ADMIN = 'SUPER_ADMIN',
  TECH_ROLE = 'TECH_ROLE',
  ADMIN = 'ADMIN',
}

@Entity()
export class User {
  @PrimaryColumn({ nullable: false })
  email: string;

  @Column()
  created_on: Date;

  @Column()
  updated_on: Date;

  @Column({ nullable: true })
  first_name: string;

  @Column({ nullable: true })
  last_name: string;

  @Column({ nullable: true })
  mobile: string;

  @Column()
  @Exclude()
  password: string;

  @Column({ type: 'varchar' })
  role: USER_ROLE;

  @Column({ nullable: true })
  is_active: boolean;
}
