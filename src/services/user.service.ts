import { UserOutputDTO } from "../dto/user.dto";
import { notFound } from "../error/NotFoundError";
import { UserMapper } from "../mapper/user.mapper";
import { User } from "../models/user.model";

export class UserService {
  // Récupère tous les utilisateurs
  public async getAllUsers(): Promise<UserOutputDTO[]> {
    let userList = await User.findAll();
    return UserMapper.toOutputDtoList(userList);
  }

  // Récupère un utilisateur par ID
  public async getUserById(id: number): Promise<UserOutputDTO> {
    let user = await User.findByPk(id);
    if (user) {
      return UserMapper.toOutputDto(user);
    } else {
      notFound("User");
    }
  }

  // Crée un nouvel utilisateur
  public async createUser(
    username: string,
    password: string,
  ): Promise<UserOutputDTO> {
    password = btoa(password);
    return UserMapper.toOutputDto(
      await User.create({ username: username, password: password }),
    );
  }

  // Supprime un utilisateur par ID
  public async deleteUser(id: number): Promise<void> {
    const user = await User.findByPk(id);
    if (user) {
      user.destroy();
    } else {
      notFound("User");
    }
  }

  // Met à jour un utilisateur
  public async updateUser(
    id: number,
    username?: string,
    password?: string,
  ): Promise<UserOutputDTO> {
    const user = await User.findByPk(id);
    if (user) {
      if (username) user.username = username;
      if (password) user.password = password;
      await user.save();
      return UserMapper.toOutputDto(user);
    } else {
      notFound("User");
    }
  }
};

export const userService = new UserService();
