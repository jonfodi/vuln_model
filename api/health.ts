import { handleApiRequest } from "../src/api/handler";

export default {
  fetch(request: Request) {
    return handleApiRequest(request);
  },
};
