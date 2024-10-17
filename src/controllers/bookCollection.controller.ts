import {
  Body,
  Controller,
  Delete,
  Get,
  Patch,
  Path,
  Post,
  Route, Security,
  Tags,
} from "tsoa";
import {
  BookCollectionInputDTO,
  BookCollectionInputPatchDTO,
  BookCollectionOutputDTO,
} from "../dto/bookCollection.dto";
import { bookCollectionService } from "../services/bookCollection.service";
@Route("book-collections")
@Tags("BookCollections")
export class BookCollectionController extends Controller {
  @Get("/")
  @Security("jwt", ["bookCollection:read"])
  public async getAllBooksCollection(): Promise<BookCollectionOutputDTO[]> {
    return bookCollectionService.getAllBookCollections();
  }

  @Get("{id}")
  @Security("jwt", ["bookCollection:read"])
  public async getBookCollection(
    @Path("id") id: number,
  ): Promise<BookCollectionOutputDTO> {
    return bookCollectionService.getBookCollectionById(id);
  }

  @Post("/")
  @Security("jwt", ["bookCollection:write"])
  public async postBookCollection(
    @Body() requestBody: BookCollectionInputDTO,
  ): Promise<BookCollectionOutputDTO> {
    return bookCollectionService.createBookCollection(
      requestBody.book_id,
      requestBody.available,
      requestBody.state,
    );
  }

  @Patch("{id}")
  @Security("jwt", ["bookCollection:update"])
  public async patchBookCollection(
    @Path("id") id: number,
    @Body() requestBody: BookCollectionInputPatchDTO,
  ): Promise<BookCollectionOutputDTO> {
    return bookCollectionService.updateBookCollection(
      id,
      requestBody.book_id,
      requestBody.available,
      requestBody.state,
    );
  }

  @Delete("{id}")
  @Security("jwt", ["bookCollection:delete"])
  public async deleteBookCollection(@Path("id") id: number): Promise<void> {
    await bookCollectionService.deleteBookCollection(id);
  }
}
