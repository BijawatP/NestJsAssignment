"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.UsersService = void 0;
const common_1 = require("@nestjs/common");
const mongoose_1 = require("@nestjs/mongoose");
const mongoose_2 = require("mongoose");
const user_schema_1 = require("./user.schema");
const bcrypt = require("bcrypt");
let UsersService = class UsersService {
    constructor(userModel) {
        this.userModel = userModel;
    }
    async create(username, password) {
        const existingUser = await this.userModel.findOne({ username }).exec();
        if (existingUser) {
            throw new common_1.ConflictException('Username already exists');
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const createdUser = new this.userModel({
            username,
            password: hashedPassword,
        });
        return createdUser.save();
    }
    async findOne(username) {
        const user = await this.userModel.findOne({ username }).exec();
        if (!user) {
            throw new common_1.NotFoundException('User not found');
        }
        return user;
    }
    async findById(id) {
        return this.userModel.findById(id).exec();
    }
    async update(userId, updateData) {
        const user = await this.userModel.findById(userId);
        if (!user) {
            throw new Error('User not found');
        }
        if (updateData.password) {
            updateData.password = await bcrypt.hash(updateData.password, 10);
        }
        if (updateData.refreshToken) {
            updateData.refreshToken = await bcrypt.hash(updateData.refreshToken, 10);
        }
        Object.assign(user, updateData);
        return user.save();
    }
    async validateUser(username, password) {
        const user = await this.userModel.findOne({ username }).exec();
        if (user && (await bcrypt.compare(password, user.password))) {
            return user;
        }
        return null;
    }
};
exports.UsersService = UsersService;
exports.UsersService = UsersService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, mongoose_1.InjectModel)(user_schema_1.User.name)),
    __metadata("design:paramtypes", [mongoose_2.Model])
], UsersService);
//# sourceMappingURL=users.service.js.map