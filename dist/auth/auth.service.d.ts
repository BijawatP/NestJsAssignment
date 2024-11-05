import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { ConfigService } from '@nestjs/config';
export declare class AuthService {
    private usersService;
    private jwtService;
    private configService;
    constructor(usersService: UsersService, jwtService: JwtService, configService: ConfigService);
    signUp(username: string, password: string): Promise<{
        access_token: string;
        refresh_token: string;
    }>;
    signIn(username: string, password: string): Promise<{
        access_token: string;
        refresh_token: string;
    }>;
    refreshTokens(userId: string, refreshToken: string): Promise<{
        access_token: string;
        refresh_token: string;
    }>;
    generateTokens(user: any): Promise<{
        access_token: string;
        refresh_token: string;
    }>;
    updateRefreshToken(userId: string, refreshToken: string): Promise<void>;
}
