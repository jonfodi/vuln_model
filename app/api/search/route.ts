import { handleApiRequest } from "../../../src/api/handler";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export const maxDuration = 30;

export function GET(request: Request) {
  return handleApiRequest(request);
}

export function POST(request: Request) {
  return handleApiRequest(request);
}

export function OPTIONS(request: Request) {
  return handleApiRequest(request);
}
