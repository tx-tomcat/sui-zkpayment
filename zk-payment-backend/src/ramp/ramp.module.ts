import { Module } from '@nestjs/common';
import { RampService } from './ramp.service';
import { RampController } from './ramp.controller';
import { BullModule } from '@nestjs/bull';
import { ProofVerifyConsumer } from './ramp.processor';

@Module({
  imports: [
    BullModule.registerQueue({
      name: 'proof-generate',
    }),
  ],
  controllers: [RampController],
  providers: [RampService, ProofVerifyConsumer],
})
export class RampModule {}
