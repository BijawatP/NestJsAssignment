import { Controller, Get, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { UsersService } from './users.service';
import { User, UserDocument } from './user.schema';
import { GetUser } from '../auth/guards/get-user.decoartor';

@Controller('users')
@UseGuards(AuthGuard('jwt'))
export class UsersController {
  constructor(private usersService: UsersService) {}

  @Get()
  async getAllUsers(@GetUser() user: UserDocument): Promise<User[]> {
    return this.usersService.findAll(user);
  }
}
