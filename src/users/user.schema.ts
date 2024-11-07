import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type UserDocument = User & Document;

// Define the Role enum
export enum UserRole {
  ADMIN = 'admin',
  USER = 'user'
}

@Schema()
export class User {
  [x: string]: any;
  @Prop({ required: true, unique: true })
  username: string;

  @Prop({ required: true })
  password: string;

  @Prop({ required: true })
  fname: string;

  // @Prop()
  lname: string;

  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true })
  dob: string;

  @Prop({ required: true })
  gender: string;

  @Prop({ required: true, enum: UserRole, default: UserRole.USER })
  role: UserRole;
}

export const UserSchema = SchemaFactory.createForClass(User);
