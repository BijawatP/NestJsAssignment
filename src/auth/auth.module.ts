import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { JwtStrategy } from './jwt.strategy';
import { UsersModule } from '../users/users.module'; // You'll need to create this
import { ConfigModule } from '@nestjs/config';
import { RefreshTokenStrategy } from './refresh-token.strategy';

@Module({
  imports: [
    UsersModule,
    PassportModule,
    JwtModule.registerAsync({
      useFactory: () => {
        console.log('JWT_SECRET:', process.env.JWT_SECRET);
        return {
          secret: process.env.JWT_SECRET,
          signOptions: { expiresIn: '1h' },
        };
      },
    }),
    ConfigModule,
  ],
  providers: [AuthService, JwtStrategy, RefreshTokenStrategy],
  controllers: [AuthController],
  exports: [AuthService],
})
export class AuthModule {}
