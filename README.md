Максим:
using System; using System.Collections.Generic; using System.IO; using System.Linq; using System.Security.Cryptography; using System.Text; using System.Text.Json; using Terminal.Gui;

namespace UserManager { enum UserRole { Client, Administrator }

class User {
    public string Login { get; set; }
    public string Salt { get; set; }
    public string PasswordHash { get; set; }
    public UserRole Role { get; set; }
}

static class UserStore {
    const string FileName = "users.json";
    public static List<User> Users { get; private set; }

    static UserStore() {
        if (File.Exists(FileName)) {
            var json = File.ReadAllText(FileName);
            Users = JsonSerializer.Deserialize<List<User>>(json) ?? new List<User>();
        } else {
            Users = new List<User>();
        }
    }

    public static void Save() {
        var json = JsonSerializer.Serialize(Users, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(FileName, json);
    }

    public static bool Exists(string login) =>
        Users.Any(u => u.Login.Equals(login, StringComparison.OrdinalIgnoreCase));

    public static void Add(string login, string password, UserRole role) {
        var salt = GenerateSalt();
        Users.Add(new User {
            Login = login,
            Salt = salt,
            PasswordHash = Hash(password, salt),
            Role = role
        });
        Save();
    }

    public static void Remove(string login) {
        Users.RemoveAll(u => u.Login.Equals(login, StringComparison.OrdinalIgnoreCase));
        Save();
    }

    public static void ChangePassword(string login, string newPassword) {
        var user = Users.First(u => u.Login.Equals(login, StringComparison.OrdinalIgnoreCase));
        user.Salt = GenerateSalt();
        user.PasswordHash = Hash(newPassword, user.Salt);
        Save();
    }

    public static bool ValidateAdmin(string login, string password) {
        var user = Users.FirstOrDefault(u => u.Login.Equals(login, StringComparison.OrdinalIgnoreCase)
                                           && u.Role == UserRole.Administrator);
        if (user == null)
            return false;
        return user.PasswordHash == Hash(password, user.Salt);
    }

    static string GenerateSalt() {
        var bytes = new byte[16];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes);
    }

    static string Hash(string input, string salt) {
        using var sha = SHA256.Create();
        var combined = Encoding.UTF8.GetBytes(input + salt);
        var hash = sha.ComputeHash(combined);
        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }
}

class Program {
    static ListView userList;
    static Window win;

    static void Main() {
        Application.Init();
        ConfigureColors();

        // Админ-вход с вводом логина и пароля
        var loginDlg = new Dialog("Admin Login", 60, 12);
        var loginField = new TextField("") { X = 1, Y = 1, Width = 40 };
        var passField  = new TextField("") { Secret = true, X = 1, Y = 4, Width = 40 };
        loginDlg.Add(new Label(1, 0, "Login:"));
        loginDlg.Add(loginField);
        loginDlg.Add(new Label(1, 3, "Password:"));
        loginDlg.Add(passField);
        loginDlg.AddButton(new Button(1, 7, "OK", is_default: true, () => {
            if (!UserStore.ValidateAdmin(loginField.Text.ToString(), passField.Text.ToString())) {
                MessageBox.ErrorQuery("Ошибка", "Неверный логин или пароль администратора.", "OK");
            } else {
                Application.RequestStop();
            }
        }));
        loginDlg.AddButton(new Button(10, 7, "Exit", is_cancel: true, () => Environment.Exit(0)));
        Application.Run(loginDlg);

// Главное окно
        win = new Window("User Manager") {
            X = 0, Y = 1, Width = Dim.Fill(), Height = Dim.Fill()
        };
        userList = new ListView(UserStore.Users.Select(u => $"{u.Login} ({u.Role})").ToList()) {
            X = 1, Y = 1, Width = 40, Height = 10
        };
        win.Add(userList);

        // Кнопки действий
        var btnAdd = new Button(45, 2, "Add User") { Clicked = AddUser };
        var btnDel = new Button(45, 4, "Delete User") { Clicked = DeleteUser };
        var btnChg = new Button(45, 6, "Change Password") { Clicked = ChangePassword };
        win.Add(btnAdd, btnDel, btnChg);

        Application.Top.Add(win);
        Application.Run();
    }

    static void RefreshList() {
        userList.SetSource(UserStore.Users.Select(u => $"{u.Login} ({u.Role})").ToList());
    }

    static void AddUser() {
        var dlg = new Dialog("Add New User", 60, 16);
        var loginField = new TextField("") { X = 1, Y = 1, Width = 40 };
        var passField  = new TextField("") { Secret = true, X = 1, Y = 4, Width = 40 };
        var roleCombo = new ComboBox() { X = 1, Y = 7, Width = 20 };
        roleCombo.SetSource(new[] { "Client", "Administrator" });

        dlg.Add(new Label(1, 0, "Login:"));      dlg.Add(loginField);
        dlg.Add(new Label(1, 3, "Password:"));   dlg.Add(passField);
        dlg.Add(new Label(1, 6, "Role:"));       dlg.Add(roleCombo);

        dlg.AddButton(new Button(1, 10, "Add", is_default: true, () => {
            var login = loginField.Text.ToString();
            var pass  = passField.Text.ToString();
            if (string.IsNullOrWhiteSpace(login) || string.IsNullOrWhiteSpace(pass)) {
                MessageBox.ErrorQuery("Ошибка", "Поля не могут быть пустыми.", "OK");
                return;
            }
            if (UserStore.Exists(login)) {
                MessageBox.ErrorQuery("Ошибка", "Пользователь с таким логином уже существует.", "OK");
                return;
            }
            var role = roleCombo.Selected == 1 ? UserRole.Administrator : UserRole.Client;
            UserStore.Add(login, pass, role);
            RefreshList();
            Application.RequestStop();
        }));
        dlg.AddButton(new Button(10, 10, "Cancel", is_cancel: true, () => Application.RequestStop()));
        Application.Run(dlg);
    }

    static void DeleteUser() {
        if (userList.Source.Count == 0) {
            MessageBox.Query("Info", "Список пользователей пуст.", "OK");
            return;
        }
        var selected = userList.Source.ToList()[userList.SelectedItem];
        if (MessageBox.Query("Confirm", $"Delete {selected}?", "Yes", "No") == 0) {
            var login = selected.Split(' ')[0];
            UserStore.Remove(login);
            RefreshList();
        }
    }

    static void ChangePassword() {
        if (userList.Source.Count == 0) {
            MessageBox.Query("Info", "Список пользователей пуст.", "OK");
            return;
        }
        var selected = userList.Source.ToList()[userList.SelectedItem];
        var login    = selected.Split(' ')[0];
        var dlg      = new Dialog($"Change Password: {login}", 60, 10);
        var passField = new TextField("") { Secret = true, X = 1, Y = 1, Width = 40 };
        dlg.Add(new Label(1, 0, "New Password:"));
        dlg.Add(passField);
        dlg.AddButton(new Button(1, 4, "Change", is_default: true, () => {
            var pass = passField.Text.ToString();
            if (string.IsNullOrWhiteSpace(pass)) {
                MessageBox.ErrorQuery("Ошибка", "Пароль не может быть пустым.", "OK");
                return;
            }
            UserStore.ChangePassword(login, pass);
            Application.RequestStop();
        }));
        dlg.AddButton(new Button(10, 4, "Cancel", is_cancel: true, () => Application.RequestStop()));
        Application.Run(dlg);
    }

static void ConfigureColors() {
        Colors.Base.Normal      = Application.Driver.MakeAttribute(Color.BrightBlue, Color.Black);
        Colors.Dialog.Normal    = Application.Driver.MakeAttribute(Color.White, Color.DarkGray);
        Colors.Menu.Normal      = Application.Driver.MakeAttribute(Color.Cyan, Color.DarkBlue);
        Colors.Menu.HotFocus    = Application.Driver.MakeAttribute(Color.BrightYellow, Color.DarkBlue);
        Colors.Error            = Application.Driver.MakeAttribute(Color.BrightRed, Color.Black);
        Application.Top.Add(new Label(1, 0, "F9=Menu    Используйте кнопки справа для операций"));
    }
}

}
