import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import 'dotenv/config';

import * as dotenv from 'dotenv';
// dotenv.config();

async function bootstrap() {
  dotenv.config();
  const app = await NestFactory.create(AppModule);
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
