import { Controller, Get, Post, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Public } from './public.decorator';

@Controller('admin')
@UseGuards(AuthGuard('jwt'))
export class AdminController {
  @Get('stats')
  stats() {
    return {};
  }

  @Public()
  @Get('ping')
  ping() {
    return 'pong';
  }
}

@Controller('notes')
export class NotesController {
  @Get()
  list() {
    return [];
  }

  @Post()
  @UseGuards(JwtAuthGuard)
  create() {
    return {};
  }

  @Get('mine')
  @Roles('admin')
  mine() {
    return [];
  }
}
