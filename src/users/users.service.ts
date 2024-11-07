import {
  Injectable,
  ConflictException,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from './user.schema';
import * as bcrypt from 'bcrypt';

const userObject = {
  fname: 1,
  email: 1,
  dob: 1,
  username: 1,
  _id:0
};

@Injectable()
export class UsersService {
  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {}

  async create(username: string, password: string, fname:string, lname:string,dob:string,gender:string,email:string,role:string): Promise<User> {
    const existingUsername = await this.userModel.findOne({ username }).exec();
    const existingEmail = await this.userModel.findOne({ email }).exec();
    if (existingUsername || existingEmail) {
      throw new ConflictException('Username or email already exist');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const createdUser = new this.userModel({
      username,
      password: hashedPassword,
      fname,
      lname,
      dob,
      gender,
      email,
      role
    });
    return createdUser.save();
  }

  async findOne(username: string): Promise<User> {
    const user = await this.userModel.findOne({ username }).exec();
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  async findById(id: string): Promise<UserDocument | null> {
    return this.userModel.findById(id).exec();
  }

  async update(
    userId: string,
    updateData: Partial<User>,
  ): Promise<UserDocument> {
    const user = await this.userModel.findById(userId);
    if (!user) {
      throw new Error('User not found');
    }

    // If updateData contains a password, hash it before saving
    if (updateData.password) {
      updateData.password = await bcrypt.hash(updateData.password, 10);
    }

    // If updateData contains a refreshToken, hash it before saving
    if (updateData.refreshToken) {
      updateData.refreshToken = await bcrypt.hash(updateData.refreshToken, 10);
    }

    Object.assign(user, updateData);
    return user.save();
  }

  async validateUser(
    username: string,
    password: string,
  ): Promise<UserDocument | null> {
    const user = await this.userModel.findOne({ username }).exec();
    if (user && (await bcrypt.compare(password, user.password))) {
      return user;
    }
    return null;
  }

  

  
  async findAll(currentUser: UserDocument): Promise<User[]> {
    // Check if the current user has the necessary permissions
    if (currentUser.role !== "admin") {
      return this.userModel.find({}, userObject).lean().exec();
    }

    // Fetch all users, excluding sensitive information
    return this.userModel.find({}, { password: 0, refreshToken: 0,__v:0 }).exec();
  }
}
