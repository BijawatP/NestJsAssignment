import {
  Injectable,
  ConflictException,
  NotFoundException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from './user.schema';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {}

  async create(username: string, password: string): Promise<User> {
    const existingUser = await this.userModel.findOne({ username }).exec();
    if (existingUser) {
      throw new ConflictException('Username already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const createdUser = new this.userModel({
      username,
      password: hashedPassword,
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
}
