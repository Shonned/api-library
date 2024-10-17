import {
  Controller,
  Get,
  Post,
  Delete,
  Route,
  Path,
  Body,
  Tags,
  Patch, Security,
} from "tsoa";
import { authorService } from "../services/author.service";
import {
  AuthorInputDTO,
  AuthorInputPatchDTO,
  AuthorOutputDTO,
} from "../dto/author.dto";
import { BookOutputDTO } from "../dto/book.dto";

@Route("authors")
@Tags("Authors")
export class AuthorController extends Controller {
  // Récupère tous les auteurs
  @Get("/")
  @Security("jwt", ["author:read"])
  public async getAllAuthors(): Promise<AuthorOutputDTO[]> {
    return authorService.getAllAuthors();
  }

  // Récupère un auteur par ID
  @Get("{id}")
  @Security("jwt", ["author:read"])
  public async getAuthorById(@Path() id: number): Promise<AuthorOutputDTO> {
    return authorService.getAuthorById(id);
  }

  // Crée un nouvel auteur
  @Post("/")
  @Security("jwt", ["author:write"])
  public async createAuthor(
    @Body() requestBody: AuthorInputDTO,
  ): Promise<AuthorOutputDTO> {
    const { first_name, last_name } = requestBody;
    return authorService.createAuthor(first_name, last_name);
  }

  // Supprime un auteur par ID
  @Delete("{id}")
  @Security("jwt", ["author:delete"])
  public async deleteAuthor(@Path() id: number): Promise<void> {
    await authorService.deleteAuthor(id);
  }

  // Met à jour un auteur par ID
  @Patch("{id}")
  @Security("jwt", ["author:update"])
  public async updateAuthor(
    @Path() id: number,
    @Body() requestBody: AuthorInputPatchDTO,
  ): Promise<AuthorOutputDTO> {
    const { first_name, last_name } = requestBody;
    return authorService.updateAuthor(id, first_name, last_name);
  }

  @Get("{id}/books")
  @Security("jwt", ["author:read"])
  public async getBooksByAuthorId(
    @Path() id: number,
  ): Promise<BookOutputDTO[]> {
    return await authorService.getBooksByAuthorId(id);
  }
}
