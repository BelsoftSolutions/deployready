import { Controller, Get, UseGuards } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';

@Controller('limited')
@UseGuards(ThrottlerGuard)
export class LimitedController {
  @Get()
  index() {
    return {};
  }
}
