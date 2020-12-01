export class PolicyConfig {
  trustedUsers: Array<string>;
  trustedGroups: Array<string>;

  constructor(users: string, groups: string) {
    this.trustedGroups = groups.split(",");
    this.trustedUsers = users.split(",");
  }

  isUserTrusted(user: string): bool {
    return this.trustedUsers.includes(user);
  }

  isGroupTrusted(group: string): bool {
    return this.trustedGroups.includes(group);
  }
}