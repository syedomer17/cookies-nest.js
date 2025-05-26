// src/auth/dto/signup.dto.ts
import { IsEmail, IsString, Matches, MinLength, ValidateIf } from 'class-validator';

export class signupDto {
  @IsString()
  name: string;

  @IsEmail()
  email: string;

  @IsString()
  @MinLength(6)
  @Matches(/^(?=.*[0-9]).+$/, { message: 'Password must contain at least one number' })
  password: string;
}