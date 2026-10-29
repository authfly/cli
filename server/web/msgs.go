package web

import "net/http"

// ruMsgs translates the server-side English messages (errText, flashes built in Go) for ru pages.
var ruMsgs = map[string]string{
	"Accept the terms to continue.":                             "Примите условия, чтобы продолжить.",
	"Enter the six-digit code from your authenticator app.":     "Введите шестизначный код из приложения-аутентификатора.",
	"See you soon.":                                             "До скорой встречи.",
	"Sign in with your new password.":                           "Войдите с новым паролем.",
	"Something went wrong. Try again in a moment.":              "Что-то пошло не так. Повторите чуть позже.",
	"The address or the password is wrong.":                     "Неверный адрес или пароль.",
	"The link is invalid or expired.":                           "Ссылка недействительна или истекла.",
	"The two passwords differ.":                                 "Пароли не совпадают.",
	"This invite is invalid, used, or expired.":                 "Приглашение недействительно, использовано или истекло.",
	"This password has expired. Reset it to continue.":          "Срок пароля истёк. Сбросьте его, чтобы продолжить.",
	"This username is reserved.":                                "Это имя зарезервировано.",
	"This username is taken.":                                   "Это имя уже занято.",
	"Verify your email address first. We sent you a new link.":  "Сначала подтвердите адрес почты. Мы отправили новую ссылку.",
	"You need an invite to create an account.":                  "Для создания аккаунта нужно приглашение.",
	"Your session expired. Try again.":                          "Сеанс истёк. Попробуйте снова.",
	"Password must have at least 10 characters.":                "Пароль должен содержать не меньше 10 символов.",
	"Username: 2 to 32 characters, lowercase letters, digits, dot, dash, underscore.": "Имя: от 2 до 32 символов — строчные буквы, цифры, точка, дефис, подчёркивание.",
	"Back to sign in": "Вернуться ко входу",
	"Too many attempts. Try again later.":                       "Слишком много попыток. Попробуйте позже.",
}

// loc returns m in the request language (messages without a translation stay English).
func (s *Server) loc(r *http.Request, m string) string {
	if m == "" || s.lang(r) != "ru" {
		return m
	}
	if t, ok := ruMsgs[m]; ok {
		return t
	}
	return m
}
