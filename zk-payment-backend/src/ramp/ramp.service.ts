import { Injectable } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bull';
import { Queue } from 'bull';

@Injectable()
export class RampService {
  constructor(@InjectQueue('proof-generate') private proofQueue: Queue) {}

  async addToQueue(eml: string | Buffer, orderId: string) {
    console.log(orderId);
    await this.proofQueue.add(
      {
        eml,
        orderId,
      },
      {
        removeOnComplete: true,
        timeout: 24 * 60 * 60 * 1000,
        attempts: 0,
        removeOnFail: true,
      },
    );
  }
}
