import { PartialType } from '@nestjs/mapped-types';
import { CreateRampDto } from './create-ramp.dto';

export class UpdateRampDto extends PartialType(CreateRampDto) {}
