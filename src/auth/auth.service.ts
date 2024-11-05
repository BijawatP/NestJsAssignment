import {
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async signUp(username: string, password: string) {
    const user = await this.usersService.create(username, password);
    // const payload = { username: user.username, sub: user._id.toString() };
    // return {
    //   user: {
    //     username: user.username,
    //     access_token: this.jwtService.sign(payload),
    //   },
    // };
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    return this.generateTokens(user);
  }

  async signIn(username: string, password: string) {
    try {
      const user = await this.usersService.validateUser(username, password);
      if (!user) {
        throw new UnauthorizedException('Invalid credentials');
      }

      const tokens = await this.generateTokens(user);
      await this.updateRefreshToken(user.id, tokens.refresh_token);

      return tokens;
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
    } catch (error) {
      throw new UnauthorizedException('Invalid credentials');
    }
  }

  async refreshTokens(userId: string, refreshToken: string) {
    const user = await this.usersService.findById(userId);
    if (!user || !user.refreshToken) {
      throw new ForbiddenException('Access Denied');
    }
    const refreshTokenMatches = await bcrypt.compare(
      refreshToken,
      user.refreshToken,
    );
    if (!refreshTokenMatches) {
      throw new ForbiddenException('Access Denied');
    }
    return this.generateTokens(user);
  }

  async generateTokens(user: any) {
    const userId = user._id.toString();
    const payload = { username: user.username, sub: userId };
    const accessToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_SECRET'),
      expiresIn: '15m',
    });
    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      expiresIn: '7d',
    });

    await this.updateRefreshToken(userId, refreshToken);

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  async updateRefreshToken(userId: string, refreshToken: string) {
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
    await this.usersService.update(userId, {
      refreshToken: hashedRefreshToken,
    });
  }
}
