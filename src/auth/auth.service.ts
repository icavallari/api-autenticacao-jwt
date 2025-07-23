import { BadRequestException, Injectable } from '@nestjs/common';
import { LoginDto } from './login.dto';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private prismaService: PrismaService,
  ) {}

  async login(loginDto: LoginDto) {
    const user = await this.prismaService.user.findUnique({
      where: { email: loginDto.email },
    });

    if (!user) {
      throw new BadRequestException('Usuário não encontrado');
    }

    const isValidPass = bcrypt.compareSync(loginDto.password, user.password);
    if (!isValidPass) {
      throw new BadRequestException('Usuário/Senha inválidos');
    }

    const token = this.jwtService.sign({
      email: user.email,
      name: user.name,
    });

    return { access_token: token };
  }
}
