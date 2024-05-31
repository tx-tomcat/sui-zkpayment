import { Test, TestingModule } from '@nestjs/testing';
import { RampController } from './ramp.controller';
import { RampService } from './ramp.service';

describe('RampController', () => {
  let controller: RampController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [RampController],
      providers: [RampService],
    }).compile();

    controller = module.get<RampController>(RampController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
