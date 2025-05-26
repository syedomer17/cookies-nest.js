import { Controller, Get, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { AuthGuard } from '@nestjs/passport';
import { User } from './auth/decorators/user.decorator';

@Controller()
export class AppController {
 @UseGuards(AuthGuard('jwt'))
 @Get()
 someProtectedRoute(@User() user: any){
  return {
    message: 'Accessed Resource',
    user,// user will contain userId, username, etc. based on your JWT strategy validate()
  }
 }
}