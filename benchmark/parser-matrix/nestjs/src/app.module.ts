import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { UsersController } from './users/users.controller';
import { AdminController } from './admin/admin.controller';

@Module({ controllers: [AppController, UsersController, AdminController] })
export class AppModule {}
