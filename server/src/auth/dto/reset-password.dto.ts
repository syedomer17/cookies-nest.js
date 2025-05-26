import { IsString, MinLength, Matches, IsNotEmpty } from 'class-validator';

export class ResetPasswordDto {
  @IsString()
  @IsNotEmpty()
  resetToken: string;

  @IsString()
  @MinLength(6)
  @Matches(/^(?=.*[0-9]).+$/, {
    message: 'Password must contain at least one number',
  })
  @IsNotEmpty()
  newPassword: string;
}
