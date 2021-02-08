import { JSON } from "assemblyscript-json";

export class PolicyConfig {
  trustedUsers: Array<String>;
  trustedGroups: Array<String>;

  constructor(settings: JSON.Obj) {
    if (settings.has("trusted_users")) {
      let u = settings.get("trusted_users") as JSON.Arr;
      this.trustedUsers = u._arr.map(function (value: JSON.Value, index: i32, array: JSON.Value[]): String {
        let v = value as JSON.Str;
        return v._str;
      });
    } else {
      this.trustedUsers = new Array<String>();
    }

    if (settings.has("trusted_groups")) {
      let g = settings.get("trusted_groups") as JSON.Arr;
      this.trustedGroups = g._arr.map(function (value: JSON.Value, index: i32, array: JSON.Value[]): String {
        let v = value as JSON.Str;
        return v._str;
      });
    } else {
      this.trustedGroups = new Array<String>();
    }
  }

  isUserTrusted(user: String): bool {
    return this.trustedUsers.includes(user);
  }

  isGroupTrusted(group: String): bool {
    return this.trustedGroups.includes(group);
  }
}