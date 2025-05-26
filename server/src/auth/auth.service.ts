import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
  NotFoundException,
  InternalServerErrorException,
} from '@nestjs/common';
import { signupDto } from './dto/signup.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User, UserDocument } from './schemas/user.schema';
import { Model, Types } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from './schemas/refresh-token.schema';
import { v4 as uuidv4 } from 'uuid';
import { nanoid } from 'nanoid';
import { ResetToken, ResetTokenDocument } from './schemas/reset-token.schema';
import { MailService } from 'src/service/mail.service';
import { OtpService } from './otp.service';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private UserModel: Model<UserDocument>,
    private jwtService: JwtService,
    @InjectModel(RefreshToken.name)
    private RefreshTokenModel: Model<RefreshToken>,
    @InjectModel(ResetToken.name)
    private resetTokenModel: Model<ResetTokenDocument>,
    private mailService: MailService,
    private readonly otpService: OtpService,
  ) {}

  // Handle user signup
  async signup(signupData: signupDto) {
    const { email, password, name } = signupData;

    if (!email) {
      throw new BadRequestException('Email must be provided');
    }

    const existingUser = await this.UserModel.findOne({ email });

    if (existingUser) {
      throw new BadRequestException('Email already in use');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await this.UserModel.create({
      name,
      email,
      password: hashedPassword,
    });

    // Corrected: only one argument here
    await this.otpService.generateOtp(email);

    return {
      message: 'Signup successful! Please verify your email.',
      user: {
        id: (newUser._id as Types.ObjectId).toString(),
        name: newUser.name,
        email: newUser.email,
      },
    };
  }

  // Handle user login
  async login(credentials: LoginDto) {
    const { email, password } = credentials;

    if (!email) {
      throw new BadRequestException('Email must be provided');
    }

    const user = (await this.UserModel.findOne({ email })) as UserDocument;

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.isEmailVerified) {
      throw new UnauthorizedException('Email not verified');
    }

    const userId = (user._id as Types.ObjectId).toString();
    const tokens = await this.generateUserToken(userId);

    return {
      message: 'Login successful!',
      user: {
        id: userId,
        name: user.name,
        email: user.email,
      },
      ...tokens,
    };
  }

  // Generate access and refresh tokens
  async generateUserToken(userId: string) {
    const accessToken = this.jwtService.sign({ userId }, { expiresIn: '1d' });
    const refreshToken = uuidv4();

    await this.storeRefreshToken(refreshToken, userId);

    return {
      accessToken,
      refreshToken,
    };
  }

  async storeRefreshToken(token: string, userId: string) {
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 3);

    await this.RefreshTokenModel.updateOne(
      { userId },
      { $set: { token, userId, expiryDate } },
      { upsert: true },
    );
  }

  // Change password
  async changePassword(
    userId: string,
    oldPassword: string,
    newPassword: string,
  ) {
    const user = await this.UserModel.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const passwordMatch = await bcrypt.compare(oldPassword, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('Wrong credentials');
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    return { message: 'Password changed successfully' };
  }

  async forgotPassword(email: string) {
    const user = await this.UserModel.findOne({ email });
    if (user) {
      const expiryDate = new Date();
      expiryDate.setHours(expiryDate.getHours() + 3);

      const resetToken = nanoid(64);

      await this.resetTokenModel.create({
        token: resetToken,
        userId: user._id,
        expiryDate,
      });

      await this.mailService.sendPasswordResetEmail(email, resetToken);
    }

    return { message: 'If this user exists, they will receive an email!' };
  }

  async resetPassword(newPassword: string, resetToken: string) {
    const token = await this.resetTokenModel.findOneAndDelete({
      token: resetToken,
      expiryDate: { $gte: new Date() },
    });

    if (!token) {
      throw new UnauthorizedException('Invalid or expired reset token');
    }

    const userId = (token.userId as Types.ObjectId).toString();

    const user = await this.UserModel.findById(userId);
    if (!user) {
      throw new InternalServerErrorException('User not found');
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    return { message: 'Password reset successfully!' };
  }

  async refreshToken(refreshToken: string) {
    const token = await this.RefreshTokenModel.findOneAndDelete({
      token: refreshToken,
      expiryDate: { $gte: new Date() },
    });

    if (!token) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    const userId = (token.userId as Types.ObjectId).toString();

    return this.generateUserToken(userId);
  }

  async verifyEmail(email: string, code: string) {
    // Corrected: only two arguments here
    await this.otpService.verifyOtp(email, code);

    await this.UserModel.findOneAndUpdate(
      { email },
      { $set: { isEmailVerified: true } },
      { new: true },
    );

    return { message: 'Email verified successfully' };
  }
}
