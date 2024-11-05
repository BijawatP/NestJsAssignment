import { AuthService } from './auth.service';
export declare class AuthController {
    private authService;
    constructor(authService: AuthService);
    signUp(signUpDto: {
        username: string;
        password: string;
    }): Promise<{
        access_token: string;
        refresh_token: string;
    }>;
    signIn(signInDto: {
        username: string;
        password: string;
    }): Promise<{
        access_token: string;
        refresh_token: string;
    }>;
    refreshTokens(req: any): Promise<{
        access_token: string;
        refresh_token: string;
    }>;
}
