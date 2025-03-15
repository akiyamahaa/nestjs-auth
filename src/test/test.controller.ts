import { Controller, Get } from '@nestjs/common';

@Controller('test')
export class TestController {
  constructor() {}

  @Get()
  async test() {
    return 'Hello world';
  }
}
