
import hashlib
import re
import requests
from getpass import getpass
import json
import os
from typing import Dict, Tuple


class PasswordChecker:
    def __init__(self):
        self.common_passwords = self.load_common_passwords()
        self.api_url = "https://api.pwnedpasswords.com/range/"

    def load_common_passwords(self) -> set:
        """Загрузка локальной базы слабых паролей"""
        common_passwords = {
            '123456', 'password', '12345678', 'qwerty', '123456789',
            '12345', '1234', '111111', '1234567', 'dragon',
            '123123', 'baseball', 'abc123', 'football', 'monkey',
            'letmein', 'shadow', 'master', '666666', 'qwertyuiop',
            '123321', 'mustang', '1234567890', 'michael', 'superman'
        }
        return common_passwords

    def calculate_password_strength(self, password: str) -> Dict:
        """Оценка сложности пароля по нескольким критериям"""
        score = 0
        feedback = []

        # Критерий 1: Длина
        if len(password) >= 12:
            score += 3
            feedback.append("✓ Длина пароля отличная (12+ символов)")
        elif len(password) >= 8:
            score += 2
            feedback.append("✓ Длина пароля хорошая (8+ символов)")
        else:
            feedback.append("✗ Слишком короткий пароль (рекомендуется 8+ символов)")

        # Критерий 2: Наличие цифр
        if re.search(r'\d', password):
            score += 1
            feedback.append("✓ Содержит цифры")
        else:
            feedback.append("✗ Добавьте цифры для увеличения сложности")

        # Критерий 3: Наличие строчных и заглавных букв
        if re.search(r'[a-z]', password) and re.search(r'[A-Z]', password):
            score += 2
            feedback.append("✓ Использует смешанный регистр")
        elif re.search(r'[a-zA-Z]', password):
            score += 1
            feedback.append("✗ Добавьте буквы в разных регистрах")

        # Критерий 4: Наличие специальных символов
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 2
            feedback.append("✓ Содержит специальные символы")
        else:
            feedback.append("✗ Добавьте специальные символы (!@#$ и т.д.)")

        # Критерий 5: Проверка на типичные слабые пароли
        if password.lower() in self.common_passwords:
            score = 0
            feedback.append("✗ Пароль находится в списке самых слабых паролей!")

        # Определение уровня безопасности
        if score >= 8:
            strength = "Отличный"
            color = "\033[92m"  # Зеленый
        elif score >= 5:
            strength = "Хороший"
            color = "\033[93m"  # Желтый
        elif score >= 3:
            strength = "Средний"
            color = "\033[33m"  # Оранжевый
        else:
            strength = "Слабый"
            color = "\033[91m"  # Красный

        return {
            'score': score,
            'max_score': 10,
            'strength': strength,
            'color': color,
            'feedback': feedback,
            'length': len(password)
        }

    def check_pwned_api(self, password: str) -> Tuple[bool, int]:
        """Проверка пароля через Have I Been Pwned API"""
        try:
            # Хеширование пароля по SHA-1
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]

            # Запрос к API
            response = requests.get(f"{self.api_url}{prefix}", timeout=5)
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for h, count in hashes:
                    if h == suffix:
                        return True, int(count)
            return False, 0
        except requests.RequestException:
            return False, -1  # Ошибка соединения

    def generate_recommendations(self, analysis: Dict, is_pwned: bool, pwned_count: int) -> list:
        """Генерация персонализированных рекомендаций"""
        recommendations = []

        if is_pwned and pwned_count > 0:
            recommendations.append(
                f"🚨 СРОЧНО: Этот пароль найден в {pwned_count} утечках! Немедленно измените его везде, где он используется.")

        if analysis['length'] < 8:
            recommendations.append(f"Увеличьте длину пароля минимум до 12 символов. Сейчас: {analysis['length']}")

        if analysis['score'] < 5:
            recommendations.append("Используйте комбинацию: заглавные + строчные буквы + цифры + специальные символы")

        recommendations.append("Не используйте один пароль на разных сайтах")
        recommendations.append("Рассмотрите использование менеджера паролей (Bitwarden, KeePass)")

        return recommendations

    def check_password(self, password: str):
        """Основная функция проверки пароля"""
        print("\n" + "=" * 50)
        print("АНАЛИЗ БЕЗОПАСНОСТИ ПАРОЛЯ")
        print("=" * 50)

        # Шаг 1: Локальный анализ сложности
        analysis = self.calculate_password_strength(password)

        # Шаг 2: Проверка через API
        print("\n[1/2] Проверка сложности пароля...")
        print(f"{analysis['color']}Оценка: {analysis['score']}/{analysis['max_score']} ({analysis['strength']})\033[0m")

        for item in analysis['feedback']:
            print(f"  {item}")

        print("\n[2/2] Проверка по базам утечек...")
        is_pwned, pwned_count = self.check_pwned_api(password)

        if is_pwned:
            print(f"\033[91m✗ Обнаружено в утечках: {pwned_count} раз(а)\033[0m")
        elif pwned_count == -1:
            print("\033[93m⚠ Проверка через API недоступна (проверьте подключение к интернету)\033[0m")
        else:
            print("\033[92m✓ Не найден в известных утечках\033[0m")

        # Шаг 3: Рекомендации
        print("\n" + "=" * 50)
        print("РЕКОМЕНДАЦИИ ПО БЕЗОПАСНОСТИ:")
        print("=" * 50)

        recommendations = self.generate_recommendations(analysis, is_pwned, pwned_count)
        for i, rec in enumerate(recommendations, 1):
            print(f"{i}. {rec}")

        # Шаг 4: Пример безопасного пароля
        print("\n" + "=" * 50)
        print("ОБРАЗЕЦ БЕЗОПАСНОГО ПАРОЛЯ:")
        print("=" * 50)
        print("• Используйте фразу: 'Кот!Любит2Спать#На$Диване'")
        print("• Или случайный набор: 'g7#Xq!29$Lp@4Rn'")
        print("\nПримечание: не используйте эти примеры как реальные пароли!")


def main():
    """Основная функция программы"""
    print("=" * 60)
    print("ПРОВЕРКА БЕЗОПАСНОСТИ ПАРОЛЕЙ")
    print("(инструмент для обучения основам кибербезопасности)")
    print("=" * 60)
    print("\nВАЖНО:")
    print("1. Программа не сохраняет проверяемые пароли")
    print("2. Для проверки используются только хеши паролей")
    print("3. Не проверяйте чужие пароли без разрешения")
    print("=" * 60)

    checker = PasswordChecker()

    while True:
        try:
            print("\nВведите пароль для проверки (или 'exit' для выхода):")
            password = input("Пароль: ")

            if password.lower() == 'exit':
                print("\nСпасибо за использование программы!")
                break

            if not password:
                print("Пароль не может быть пустым!")
                continue

            # Проверка пароля
            checker.check_password(password)

            print("\n" + "=" * 60)
            print("ЭТИЧЕСКОЕ ИСПОЛЬЗОВАНИЕ:")
            print("=" * 60)
            print("Этот инструмент предназначен только для:")
            print("• Проверки СВОИХ паролей")
            print("• Обучения основам безопасности")
            print("• Демонстрации на уроках информатики")
            print("\nНе используйте для проверки паролей других людей!")

        except KeyboardInterrupt:
            print("\n\nПрограмма завершена.")
            break
        except Exception as e:
            print(f"\nПроизошла ошибка: {e}")
            print("Попробуйте еще раз.")


if __name__ == "__main__":
    main()