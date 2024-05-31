import {
  Controller,
  Post,
  UseInterceptors,
  UploadedFile,
  Body,
} from '@nestjs/common';
import { RampService } from './ramp.service';
import { FileInterceptor } from '@nestjs/platform-express';

@Controller('ramp')
export class RampController {
  constructor(private readonly rampService: RampService) {}

  @Post('upload')
  @UseInterceptors(FileInterceptor('file'))
  async uploadFile(
    @UploadedFile()
    file: Express.Multer.File,
    @Body() body,
  ) {
    await this.rampService.addToQueue(file.buffer.toString(), body.orderId);
  }
}
