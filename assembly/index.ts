import { JSON } from "assemblyscript-json";
import { validate, settingsValidated } from "./validate";

import {
  register,
  handleCall,
  handleAbort,
} from "@wapc/as-guest";

register("validate", function (payload: ArrayBuffer): ArrayBuffer {
  let validation_request = JSON.parse(String.UTF8.decode(payload, false)) as JSON.Obj;
  let req = validation_request.get("request") as JSON.Obj;

  return String.UTF8.encode(validate(req));
})

register("validate_settings", function (payload: ArrayBuffer): ArrayBuffer {
  return String.UTF8.encode(settingsValidated());
})

register("protocol_version", function (payload: ArrayBuffer): ArrayBuffer {
  return String.UTF8.encode('"v1"');
})


// This must be present in the entry file.
export function __guest_call(operation_size: usize, payload_size: usize): bool {
  return handleCall(operation_size, payload_size);
}

// Abort function
function abort(message: string | null, fileName: string | null, lineNumber: u32, columnNumber: u32): void {
  handleAbort(message, fileName, lineNumber, columnNumber)
}