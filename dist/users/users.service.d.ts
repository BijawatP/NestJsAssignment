import { Model } from 'mongoose';
import { User, UserDocument } from './user.schema';
export declare class UsersService {
    private userModel;
    constructor(userModel: Model<UserDocument>);
    create(username: string, password: string): Promise<User>;
    findOne(username: string): Promise<User>;
    findById(id: string): Promise<UserDocument | null>;
    update(userId: string, updateData: Partial<User>): Promise<UserDocument>;
    validateUser(username: string, password: string): Promise<UserDocument | null>;
}
