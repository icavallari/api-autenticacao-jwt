import { BadRequestException, Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import { Prisma, User } from '@prisma/client';
import bcrypt from 'bcrypt';

type UserWithoutPassword = Omit<User, 'password'>;

@Injectable()
export class UsersService {
  constructor(private prismaService: PrismaService) {}

  async create(createUserDto: CreateUserDto): Promise<UserWithoutPassword> {
    const hashedPassword = await this.encriptPassword(createUserDto.password);

    await this.checkIfEmailExists(createUserDto.email);

    const user = await this.prismaService.user.create({
      data: {
        ...createUserDto,
        password: hashedPassword,
      },
    });
    return this.removePassword(user);
  }

  async findAll(): Promise<UserWithoutPassword[]> {
    const users = await this.prismaService.user.findMany();
    return users.map((user) => this.removePassword(user));
  }

  async findOne(id: string): Promise<UserWithoutPassword | null> {
    const user = await this.prismaService.user.findUnique({
      where: { id },
    });

    return user ? this.removePassword(user) : null;
  }

  async update(
    id: string,
    updateUserDto: UpdateUserDto,
  ): Promise<UserWithoutPassword> {
    if (updateUserDto.password) {
      updateUserDto.password = await this.encriptPassword(
        updateUserDto.password,
      );
    }

    const user = await this.prismaService.user.update({
      where: { id },
      data: updateUserDto,
    });

    return this.removePassword(user);
  }

  async remove(id: string): Promise<UserWithoutPassword | null> {
    return await this.prismaService.user.delete({
      where: { id },
    });
  }

  async findBy(params: {
    where?: Prisma.UserWhereInput;
  }): Promise<UserWithoutPassword[]> {
    return await this.prismaService.user.findMany({
      where: params.where,
    });
  }

  async encriptPassword(password: string): Promise<string> {
    return await bcrypt.hash(password, 10);
  }

  async checkIfEmailExists(email: string): Promise<void> {
    const user = await this.findBy({
      where: {
        email,
      },
    });

    if (user) {
      throw new BadRequestException('E-mail já cadastrado');
    }
  }

  removePassword(user: User): UserWithoutPassword {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, ...userWithoutPassword } = user;
    return userWithoutPassword;
  }
}
