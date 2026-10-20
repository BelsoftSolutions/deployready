import { Controller, Delete, Get, Param, UseGuards } from '@nestjs/common';
import { AuthGuard } from '../auth/auth.guard';

@Controller('admin')
@UseGuards(AuthGuard)
export class AdminController {
  @Get('stats')
  stats() {
    return { users: 0 };
  }

  @Delete('users/:id')
  remove(@Param('id') id: string) {
    return { deleted: id };
  }
}
