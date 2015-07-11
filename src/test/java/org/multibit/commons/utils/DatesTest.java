package org.multibit.commons.utils;

import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;
import org.joda.time.DateTimeZone;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.Locale;
import java.util.TimeZone;

import static org.fest.assertions.api.Assertions.assertThat;

public class DatesTest {

  // Get the current timezone without using Joda time
  TimeZone original = TimeZone.getDefault();

  @Before
  public void setUp() throws Exception {

    // We work in the UK locale under GMT+2 for consistency
    Locale.setDefault(Locale.UK);
    DateTimeUtils.setCurrentMillisFixed(new DateTime(2000, 1, 1, 23, 59, 58, 999, DateTimeZone.UTC).getMillis());
    DateTimeZone.setDefault(DateTimeZone.forOffsetHours(2));

  }

  @After
  public void tearDown() throws Exception {

    // Ensure any changes are returned to UK locale
    Locale.setDefault(Locale.UK);
    DateTimeUtils.setCurrentMillisSystem();
    DateTimeZone.setDefault(DateTimeZone.forID(original.getID()));

  }

  @Test
  public void testMidnightUtc() {

    DateTimeUtils.setCurrentMillisFixed(new DateTime(2000, 1, 2, 3, 4, 5, 6, DateTimeZone.UTC).getMillis());

    assertThat(Dates.formatIso8601(Dates.midnightUtc())).isEqualTo("2000-01-02T00:00:00Z");
  }

  @Test
  public void testShortTime_DefaultLocale() {

    assertThat(Dates.formatShortTime(Dates.nowUtc())).isEqualTo("23:59");
    assertThat(Dates.formatShortTimeLocal(Dates.nowUtc())).isEqualTo("01:59");

  }

  @Test
  public void testFormatTransaction_DefaultLocale() {

    assertThat(Dates.formatTransactionDate(Dates.nowUtc())).isEqualTo("01 Jan 2000 23:59");
    assertThat(Dates.formatTransactionDateLocal(Dates.nowUtc())).isEqualTo("02 Jan 2000 01:59");

  }

  @Test
  public void testFormatTransaction_FrenchLocale() {

    assertThat(Dates.formatTransactionDate(Dates.nowUtc(), Locale.FRANCE)).isEqualTo("01 janv. 2000 23:59");
    assertThat(Dates.formatTransactionDateLocal(Dates.nowUtc(), Locale.FRANCE)).isEqualTo("02 janv. 2000 01:59");

  }

  @Test
  public void testFormatTransaction_ThaiLocale() {

    assertThat(Dates.formatTransactionDate(Dates.nowUtc(), new Locale("th", "TH", "TH"))).isEqualTo("01 ม.ค. 2000 23:59");
    assertThat(Dates.formatTransactionDateLocal(Dates.nowUtc(), new Locale("th", "TH", "TH"))).isEqualTo("02 ม.ค. 2000 01:59");

  }

  @Test
  public void testFormatDelivery_DefaultLocale() {

    assertThat(Dates.formatDeliveryDate(Dates.nowUtc())).isEqualTo("Saturday, January 01");
    assertThat(Dates.formatDeliveryDateLocal(Dates.nowUtc())).isEqualTo("Sunday, January 02");

  }

  @Test
  public void testFormatDelivery_FrenchLocale() {

    assertThat(Dates.formatDeliveryDate(Dates.nowUtc(), Locale.FRANCE)).isEqualTo("samedi, janvier 01");
    assertThat(Dates.formatDeliveryDateLocal(Dates.nowUtc(), Locale.FRANCE)).isEqualTo("dimanche, janvier 02");

  }

  @Test
  public void testFormatDelivery_ThaiLocale() {

    assertThat(Dates.formatDeliveryDate(Dates.nowUtc(), new Locale("th", "TH", "TH"))).isEqualTo("วันเสาร์, มกราคม 01");
    assertThat(Dates.formatDeliveryDateLocal(Dates.nowUtc(), new Locale("th", "TH", "TH"))).isEqualTo("วันอาทิตย์, มกราคม 02");
  }

  @Test
  public void testFormatSmtp_DefaultLocale() {

    assertThat(Dates.formatSmtpDate(Dates.nowUtc())).isEqualTo("01 Jan 2000");
    assertThat(Dates.formatSmtpDateLocal(Dates.nowUtc())).isEqualTo("02 Jan 2000");

  }

  @Test
  public void testFormatSmtp_FrenchLocale() {

    assertThat(Dates.formatSmtpDate(Dates.nowUtc(), Locale.FRANCE)).isEqualTo("01 janv. 2000");
    assertThat(Dates.formatSmtpDateLocal(Dates.nowUtc())).isEqualTo("02 Jan 2000");

  }

  @Test
  public void testFormatSmtp_ThaiLocale() {

    assertThat(Dates.formatSmtpDate(Dates.nowUtc(), new Locale("th", "TH", "TH"))).isEqualTo("01 ม.ค. 2000");
    assertThat(Dates.formatSmtpDateLocal(Dates.nowUtc())).isEqualTo("02 Jan 2000");

  }

  @Test
  public void testParseISO8601_DefaultLocale() {

    DateTime instant = Dates.parseIso8601("2000-01-01T12:00:00Z");

    assertThat(Dates.formatIso8601(instant)).isEqualTo("2000-01-01T12:00:00Z");
    assertThat(Dates.formatIso8601Local(instant)).isEqualTo("2000-01-01T14:00:00+02:00");

  }

  @Test
  public void testParseSmtpUtc_DefaultLocale() {

    DateTime instant = Dates.parseSmtpUtc("01 Jan 2000").withZone(DateTimeZone.UTC);
    assertThat(Dates.formatIso8601(instant)).isEqualTo("2000-01-01T00:00:00Z");
    assertThat(Dates.formatIso8601Local(instant)).isEqualTo("2000-01-01T02:00:00+02:00");

    instant = Dates.parseSmtpUtc("1 jan 2000").withZone(DateTimeZone.UTC);
    assertThat(Dates.formatIso8601(instant)).isEqualTo("2000-01-01T00:00:00Z");
    assertThat(Dates.formatIso8601Local(instant)).isEqualTo("2000-01-01T02:00:00+02:00");

    instant = Dates.parseSmtpUtc("1 january 2000").withZone(DateTimeZone.UTC);
    assertThat(Dates.formatIso8601(instant)).isEqualTo("2000-01-01T00:00:00Z");
    assertThat(Dates.formatIso8601Local(instant)).isEqualTo("2000-01-01T02:00:00+02:00");

  }

  @Test
  public void testParseSmtpUtc_FrenchLocale() {

    DateTime instant = Dates.parseSmtpUtc("01 janv. 2000", Locale.FRANCE).withZone(DateTimeZone.UTC);
    assertThat(Dates.formatIso8601(instant)).isEqualTo("2000-01-01T00:00:00Z");
    assertThat(Dates.formatIso8601Local(instant)).isEqualTo("2000-01-01T02:00:00+02:00");

  }

  @Test
  public void testParseSmtpUtc_ThaiLocale() {

    DateTime instant = Dates.parseSmtpUtc("01 ม.ค. 2000", new Locale("th", "TH", "TH")).withZone(DateTimeZone.UTC);
    assertThat(Dates.formatIso8601(instant)).isEqualTo("2000-01-01T00:00:00Z");
    assertThat(Dates.formatIso8601Local(instant)).isEqualTo("2000-01-01T02:00:00+02:00");

  }

  @Test
  public void testNewSeedTimestamp() {

    DateTimeUtils.setCurrentMillisFixed(new DateTime(2014, 1, 27, 0, 0, 0, 0, DateTimeZone.UTC).getMillis());
    assertThat(Dates.newSeedTimestamp()).isEqualTo("1850/07");

    DateTimeUtils.setCurrentMillisFixed(new DateTime(2014, 1, 17, 0, 0, 0, 0, DateTimeZone.UTC).getMillis());
    assertThat(Dates.newSeedTimestamp()).isEqualTo("1840/94");

  }

  @Test
  public void testParseSeedTimestamp() {

    DateTime expected = new DateTime(2014, 1, 17, 0, 0, 0, 0, DateTimeZone.UTC);

    assertThat(Dates.parseSeedTimestamp("1840/94")).isEqualTo(expected);

  }

  @Test(expected = IllegalArgumentException.class)
  public void testParseSeedTimestamp_Checksum() {

    DateTime expected = new DateTime(2014, 1, 27, 0, 0, 0, 0, DateTimeZone.UTC);

    assertThat(Dates.parseSeedTimestamp("1850/01")).isEqualTo(expected);

  }

  @Test(expected = IllegalArgumentException.class)
  public void testParseSeedTimestamp_Length() {

    DateTime expected = new DateTime(2014, 1, 27, 0, 0, 0, 0, DateTimeZone.UTC);

    assertThat(Dates.parseSeedTimestamp("180/12")).isEqualTo(expected);

  }

  @Test(expected = IllegalArgumentException.class)
  public void testParseSeedTimestamp_Format1() {

    DateTime expected = new DateTime(2014, 1, 27, 0, 0, 0, 0, DateTimeZone.UTC);

    assertThat(Dates.parseSeedTimestamp("1850-20")).isEqualTo(expected);

  }

  @Test(expected = IllegalArgumentException.class)
  public void testParseSeedTimestamp_Format2() {

    DateTime expected = new DateTime(2014, 1, 27, 0, 0, 0, 0, DateTimeZone.UTC);

    assertThat(Dates.parseSeedTimestamp("1850/")).isEqualTo(expected);

  }

  // Must ignore since this may fail on non-internet connected systems
  @Ignore
  public void testCalculateDriftInMillis() throws IOException {

    Dates.calculateDriftInMillis("pool.ntp.org");

  }

  // Must ignore since this may fail on non-internet connected systems
  @Ignore
  @Test(expected = SocketTimeoutException.class)
  public void testCalculateDriftInMillis_Timeout() throws IOException {

    Dates.calculateDriftInMillis("example.org");

  }

}
